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
//! above. The source system is dark only; the light ramp further down is this
//! console's own derivation, re-pointing the semantic tokens and nothing else,
//! because an enterprise console is used in daylight beside other documents.
//! (An earlier version of this header said no light ramp would be invented —
//! that predates the block that invented one.)
//!
//! The typefaces diverge the other way since the 2026-08 smoothing pass: the
//! *platform's* face leads every stack and the system's named faces (Space
//! Grotesk, IBM Plex Sans, JetBrains Mono) are fallbacks. They used to lead —
//! exact on a workstation that had them, rougher everywhere else, since a
//! third-party face is not tuned for the local rasteriser the way the
//! platform's own is. Nothing is embedded and nothing is fetched, by the same
//! rule as everything else on the page.
//!
//! ## The token never touches disk
//!
//! The page itself is public — markup with no data in it, and a sign-in form
//! that cannot be reached is not a sign-in form. Every byte of data behind it
//! needs the same bearer token the API requires, held in `sessionStorage` so it
//! is gone when the tab closes: an appliance token has no business outliving the
//! session on a shared machine.

/// The tab icon, served at `/favicon.ico` — a 16×16 PNG, a few dozen bytes.
///
/// Browsers ask for it on every load whether the page names one or not, and
/// a console with none answered every load with a 404 that landed in the API
/// log and the browser console. Served as bytes rather than named by a
/// `<link>`: the page stays self-contained, and a `<link>` is exactly what
/// [`tests::the_page_is_self_contained`] refuses.
pub const FAVICON_PNG: &[u8] = &[137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 16, 0, 0, 0, 16, 8, 6, 0, 0, 0, 31, 243, 255, 97, 0, 0, 0, 39, 73, 68, 65, 84, 120, 218, 99, 96, 160, 22, 144, 207, 239, 254, 79, 10, 30, 53, 96, 212, 0, 218, 24, 64, 138, 33, 20, 37, 105, 138, 242, 5, 69, 153, 139, 129, 86, 0, 0, 75, 73, 53, 240, 89, 14, 85, 95, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130];

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

      --bg-app: #f8fafc; --surface: #ffffff;
      --surface-raised: #ffffff; --surface-sunken: #f1f5f9;
      --surface-hover: #eef2f7;
      /* The rail stays a shade off the page in both appearances: a console
         reads as navigation-plus-content, and two identical whites collapse
         that into one sheet. */
      --sidebar-bg: #f1f5f9;
      --text-strong: #0f172a; --text-body: #1e293b;
      --text-muted: #64748b; --text-faint: #94a3b8;
      --border: #e2e8f0; --border-strong: #cbd5e1;
      --border-subtle: rgba(15,23,42,.07);
      /* The accent darkens on white so a link and a focus ring still pass AA
         at 4.5:1; the dark ramp's lighter cyan would not. */
      --brand: #1f7fa8; --brand-hover: #186a8e;
      --brand-active: #145b7a; --focus-ring: #1f7fa8;
      --link: #1f7fa8;
      --green-500: #047857; --amber-500: #b45309; --red-500: #b91c1c;
      --green-300: #047857; --amber-300: #b45309; --red-300: #b91c1c;
      --cyan-500: #1f7fa8; --meter: #94a3b8;
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

    --ink-950: #080c11; --ink-900: #0b0f14; --ink-850: #10161d;
    --ink-800: #141a22; --ink-700: #19212b; --ink-600: #1d2630;
    --ink-500: #2a3441; --ink-400: #3a4658; --ink-300: #5c6b80;
    --slate-400: #8b9bb0; --slate-100: #e8edf2; --white: #f4f8fb;

    /* Signal is the interaction colour and nothing else — a cool blue-cyan
       rather than the framework blue it used to be. It marks what answers the
       operator: links, focus, selection, the active view, the one primary
       action. It never means "healthy" and it never fills a utilisation bar. */
    --signal-300: #7cc4e0; --signal-400: #4fb2dc; --signal-500: #2e96c4;
    --signal-600: #2179a1; --signal-900: #0f2c3a;
    --sentinel-500: #f59e0b; --sentinel-600: #d18509; --sentinel-900: #45260a;

    --green-500: #10b981; --amber-500: #f59e0b; --red-500: #ef4444;
    /* The same three at text weight: a coloured word needs more lightness on a
       dark surface than the dot beside it. */
    --green-300: #34d399; --amber-300: #fbbf24; --red-300: #f87171;
    --cyan-500: #2e96c4;

    /* Utilisation is information, not interaction: its bar stays neutral and
       only takes a status colour near or at a limit. */
    --meter: #55647a;

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

    /* The platform's own face first. Every OS ships one that is tuned for
       its rasteriser — optical sizing, hinting, the lot — and a third-party
       face that happens to be installed renders *rougher* than the system one,
       not more designed. The named faces stay as fallbacks for a system whose
       default is genuinely poor. */
    --font-display: system-ui, -apple-system, "Space Grotesk", "Segoe UI", sans-serif;
    --font-sans: system-ui, -apple-system, "IBM Plex Sans", "Segoe UI", sans-serif;
    --font-mono: "JetBrains Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    --fw-regular: 400; --fw-medium: 500; --fw-semibold: 600;
    --text-2xs: .6875rem; --text-xs: .75rem; --text-sm: .8125rem;
    --text-base: .875rem; --text-lg: 1.125rem; --text-xl: 1.5rem;
    /* The stat tiles have asked for this size since they were written; it was
       never defined, the whole `font:` shorthand naming it was silently
       invalid, and every headline number on the dashboard rendered at body
       size. The one figure a tile exists to show was its smallest text. */
    --text-2xl: 1.75rem;
    --leading-tight: 1.1; --leading-snug: 1.28; --leading-normal: 1.55;
    --leading-code: 1.45;
    /* Tracking is a function of size, not one number for the whole page: as
       type grows the counters open up and the letters read too far apart, and
       as it shrinks they close and want a little air. Three steps — display,
       heading, body — plus the caps run, which is a different job. */
    --tracking-display: -.025em; --tracking-tight: -.015em;
    --tracking-body: 0em; --tracking-small: .01em; --tracking-caps: .08em;

    --space-1: .25rem; --space-2: .5rem; --space-3: .75rem; --space-4: 1rem;
    --space-5: 1.25rem; --space-6: 1.5rem; --space-7: 2rem; --space-9: 3rem;
    --sidebar-w: 268px;

    /* The one gutter. Every label on the page — a group heading, the command a
       pane is showing — stands in a margin column of this width, so the page
       has exactly one left edge for labels and one for content. 180 + 28 is
       208, which is also the width the widest ordinary field takes: the
       measure is shared rather than invented twice. */
    --gutter: 180px; --gutter-gap: 28px;

    /* Soft, in one ramp. The structure is still hairlines and space — the
       radii are small enough that nothing reads as a bubble — but a control an
       operator touches all day should not have the corners of a spreadsheet
       cell. Ordered by what a thing is: chips take xs, controls sm, panes md,
       cards lg. (This supersedes the earlier all-square decision on purpose:
       squareness made the console read as a terminal, and a terminal is what
       the CLI is for.) */
    /* Restrained: an appliance surface is a region of a structured page, not a
       card you could pick up. 4px default, 6px the largest ordinary surface. */
    --radius-xs: 3px; --radius-sm: 4px; --radius-md: 4px; --radius-lg: 6px;
    /* The header bar's height, shared with everything that must stop under it
       (the edit drawer, the add drawers). */
    --bar-h: 60px;
    --radius-pill: 999px;

    /* Wider and lighter than before: a shadow is one light source doing its
       job, not an outline drawn in black. */
    --shadow-sm: 0 1px 3px rgba(0,0,0,.28);
    --shadow-md: 0 6px 18px rgba(0,0,0,.32);
    --shadow-lg: 0 18px 44px rgba(0,0,0,.42);
    --edge-top: inset 0 1px 0 rgba(255,255,255,.05);
    --glow-focus: 0 0 0 3px rgba(76,141,255,.35);
    /* A single cool wash behind the shell. Flat charcoal reads as a terminal;
       one light source is what makes a console read as a surface. */
    --wash: radial-gradient(1200px 520px at 82% -14%, rgba(76,141,255,.13), transparent 60%);

    /* Motion, of which this console has deliberately little: an operator sees
       these screens all day, and the rule is that anything opened dozens of
       times a day either moves imperceptibly or not at all. What does move
       borrows its curve rather than inventing one — a hand-rolled bezier is
       how an interface ends up with five nearly identical ones that disagree.
       `--ease-out` is the strong UI ease-out (entering and leaving),
       `--ease-in-out` is for something moving on screen, and hover and colour
       keep the browser's own `ease`, which is what that case wants. */
    --dur-fast: 130ms; --dur-base: 200ms;
    --ease-out: cubic-bezier(0.23, 1, 0.32, 1);
    --ease-in-out: cubic-bezier(0.77, 0, 0.175, 1);
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
    /* Light-on-dark text blooms; grayscale antialiasing takes the fringing
       off and is most of what "smoother type" turns out to mean. */
    -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale;
    font: var(--fw-regular) var(--text-base)/var(--leading-normal) var(--font-sans);
    -webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility;
  }}
  h1, h2, h3 {{
    margin: 0; color: var(--text-strong); font-family: var(--font-display);
    font-weight: var(--fw-semibold); letter-spacing: var(--tracking-body);
    line-height: var(--leading-snug);
  }}
  /* The three headings that are actually larger than the body. Everything else
     called h1/h2/h3 is body-sized or a small-caps rule, and tightening those
     only made them harder to read. */
  aside h1, .bar h2, .section h3 {{ letter-spacing: var(--tracking-tight); }}
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
    font: var(--fw-medium) var(--text-xs)/1.2 var(--font-sans);
    letter-spacing: var(--tracking-body);
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
    min-height: var(--bar-h); box-sizing: border-box;
    padding: var(--space-2) var(--space-7);
    border-bottom: 1px solid var(--border-subtle);
    /* Opaque, like every non-floating surface: content scrolls up to an edge,
       not into a blur. */
    background: var(--bg-app);
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
    letter-spacing: var(--tracking-display);
    margin: 0 0 var(--space-2);
  }}
  /* Tables are read, not admired: a sticky header so the columns stay named
     while scrolling, tabular numerals so figures line up, and a hairline
     between rows instead of zebra stripes, which fight the status colours. */
  table {{ width: 100%; border-collapse: collapse; font-size: var(--text-sm); }}
  table th {{
    position: sticky; top: 0; z-index: 1;
    background: var(--surface); text-align: left;
    font: var(--fw-medium) var(--text-xs)/1.2 var(--font-sans);
    letter-spacing: var(--tracking-body);
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

  /* A live state is a dot and a coloured word, not a framed tablet: a page of
     bordered pills turns into a field of ornaments and the one DOWN that
     matters stops standing out. The dot keeps colour from being the only
     channel; the word carries the meaning. */
  .pill {{
    display: inline-flex; align-items: center; gap: var(--space-2);
    font: var(--fw-medium) var(--text-xs)/1.6 var(--font-sans);
    letter-spacing: var(--tracking-body);
    color: var(--text-muted); white-space: nowrap;
  }}
  .pill::before {{
    content: ""; width: 7px; height: 7px; border-radius: var(--radius-pill);
    background: var(--text-faint); flex: none;
  }}
  /* The resting state whispers — no dot, no frame, just faint text. */
  .pill.rest {{ color: var(--text-faint); }}
  .pill.rest::before {{ display: none; }}
  .pill.up, .pill.ok {{ color: var(--green-300); }}
  .pill.up::before, .pill.ok::before {{ background: var(--status-up); }}
  .pill.down {{ color: var(--red-300); }}
  .pill.down::before {{ background: var(--status-down); }}

  /* --- surfaces --------------------------------------------------------- */
  .card {{
    border: 1px solid var(--border); border-radius: var(--radius-lg);
    background: var(--surface);
    padding: var(--space-5); margin: 0 0 var(--space-4);
  }}
  .card > h3 {{
    font: var(--fw-semibold) var(--text-xs)/1.2 var(--font-sans);
    letter-spacing: var(--tracking-body);
    color: var(--text-muted); margin: 0 0 var(--space-3);
  }}
  /* auto-fill, not auto-fit: two service tiles beside four counters stretched
     to half the page each and stopped reading as the same kind of thing. An
     empty column is better than a tile the width of a paragraph. */
  /* Like .stats: one bordered strip whose cells share dividers, not a grid of
     floating tiles. The dashboard's daemon states and counters are readings on
     one instrument, and the border belongs to the instrument. */
  .cards {{
    display: flex; flex-wrap: wrap; margin-bottom: var(--space-4);
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius-lg); overflow: hidden;
  }}
  .cards:empty {{ display: none; }}
  .cards .kpi {{
    border: 0; border-right: 1px solid var(--border-subtle); border-radius: 0;
    flex: 1 1 11rem; padding: var(--space-3) var(--space-4);
  }}
  .cards .kpi:last-child {{ border-right: 0; }}
  .cards .kpi:hover {{ border-color: var(--border-subtle); }}
  .metric {{
    font: var(--fw-semibold) var(--text-lg)/var(--leading-tight) var(--font-sans);
    font-variant-numeric: tabular-nums; color: var(--text-strong);
  }}
  .metric small {{
    font: var(--fw-regular) var(--text-xs)/1.2 var(--font-mono);
    color: var(--text-muted); margin-left: var(--space-2);
  }}
  .metric.ok {{ color: var(--status-up); }}
  .metric.err {{ color: var(--status-down); }}
  canvas {{ width: 100%; height: 48px; display: block; margin-top: var(--space-2); }}

  /* A pane that scrolls sideways gets a thin bar, not the browser's gutter
     furniture — the stub under the interfaces table was the heaviest line in
     its card. Firefox first, then the WebKit parts. */
  pre.out, .tblwrap, .scroll-x {{
    scrollbar-width: thin;
    scrollbar-color: var(--ink-400) transparent;
  }}
  pre.out::-webkit-scrollbar, .tblwrap::-webkit-scrollbar,
  .scroll-x::-webkit-scrollbar {{ height: 6px; width: 6px; }}
  pre.out::-webkit-scrollbar-thumb, .tblwrap::-webkit-scrollbar-thumb,
  .scroll-x::-webkit-scrollbar-thumb {{
    background: var(--ink-400); border-radius: var(--radius-pill);
  }}
  pre.out::-webkit-scrollbar-track, .tblwrap::-webkit-scrollbar-track,
  .scroll-x::-webkit-scrollbar-track {{ background: transparent; }}

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
    font: var(--fw-semibold) var(--text-xs)/1.2 var(--font-sans);
    letter-spacing: var(--tracking-body);
    color: var(--text-faint); border-bottom-color: var(--border-strong);
    white-space: nowrap;
  }}
  tbody tr:hover, tr:hover {{ background: var(--surface-raised); }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; font-family: var(--font-mono); }}
  /* A value that is a sentence — the image identity, a list of addresses —
     is prose, and right-aligned wrapped prose is unreadable in exact
     proportion to its importance. Numerals keep `num`; words get this. */
  td.val {{
    font-family: var(--font-mono); font-size: var(--text-sm);
    text-align: left; overflow-wrap: anywhere; color: var(--text-body);
  }}
  /* pre-line keeps one address per line; `anywhere` stays on so an address
     longer than the column still breaks instead of dragging a scrollbar in —
     between the two, a break inside one address is the rarer event. */
  td.val.lines {{ white-space: pre-line; }}
  tr.zero td {{ color: var(--text-faint); }}

  /* --- controls --------------------------------------------------------- */
  input, select, textarea, button.btn {{
    font: inherit; font-size: var(--text-sm); color: var(--text-body);
    padding: var(--space-2) var(--space-3); border-radius: var(--radius-sm);
    border: 1px solid var(--border); background: var(--surface-sunken);
    transition: border-color var(--dur-fast) ease, background var(--dur-fast) ease,
                box-shadow var(--dur-fast) ease;
  }}
  input:hover, select:hover, textarea:hover {{ border-color: var(--border-strong); }}
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
    transition: background var(--dur-fast) ease, color var(--dur-fast) ease,
                border-color var(--dur-fast) ease,
                transform var(--dur-fast) var(--ease-out);
  }}
  /* The press is acknowledged on the way DOWN. Feedback that waits for the
     release reads as lag, and this is the one transform the motion rules
     allow everywhere: it happens under the pointer, at the pointer's moment. */
  button.btn:active {{ transform: scale(.97); }}
  @media (prefers-reduced-motion: reduce) {{
    button.btn:active {{ transform: none; }}
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
  /* A setting with two states and the condition of not having been set.
     Unset is deliberately inert — a hairline track, the knob at rest, no fill —
     because "off" is a decision somebody made and "not set" is not, and a
     control that draws them the same way is a control that lies about which
     one is in front of you. */
  .switch {{ display: inline-flex; align-items: center; gap: var(--space-2); }}
  /* The value, kept out of sight: one control to operate, one value to read.
     `display: none` rather than a clipped box, so it is out of the tab order
     and the accessibility tree without being told to be, and so anything that
     walks the page for controls finds the switch and not a second one behind
     it. A hidden `<select>` still answers to `.value`, which is all this is. */
  .switch .carrier {{ display: none; }}
  .knob {{
    position: relative; flex: none; width: 34px; height: 20px; padding: 0;
    border: 1px solid var(--border-strong); border-radius: var(--radius-pill);
    background: var(--surface-sunken); cursor: pointer;
    transition: background var(--dur-fast) ease, border-color var(--dur-fast) ease;
  }}
  .knob::after {{
    content: ""; position: absolute; inset: 2px auto 2px 2px;
    width: 14px; border-radius: var(--radius-pill); background: var(--text-faint);
    transition: transform var(--dur-fast) var(--ease-out),
                background var(--dur-fast) ease;
  }}
  .knob[data-state="unset"] {{ border-style: dashed; }}
  .knob[data-state="false"] {{ border-color: var(--border-strong); }}
  .knob[data-state="false"]::after {{ background: var(--text-muted); }}
  .knob[data-state="true"] {{ background: var(--brand); border-color: var(--brand); }}
  .knob[data-state="true"]::after {{
    background: var(--on-brand); transform: translateX(14px);
  }}
  .knob:hover {{ border-color: var(--brand); }}
  /* One switch carries one decision; the way back to "not set" must be there
     without adding a second bordered control beside every one of them. */
  .switch .suggest {{ margin-left: 0; border-color: transparent; background: none; }}
  .switch .suggest:hover {{ border-color: var(--brand); background: var(--surface-raised); }}
  .switchstate {{
    font: var(--fw-regular) var(--text-2xs)/1.4 var(--font-mono);
    color: var(--text-faint); letter-spacing: var(--tracking-small);
    white-space: nowrap;
  }}
  /* A whole number and what it is counted in. The unit rides the value rather
     than the label, so the label can say what the setting is and the box can
     say what the figure means. */
  .num {{ display: inline-flex; align-items: center; gap: var(--space-2); }}
  .unit {{
    font: var(--fw-regular) var(--text-2xs)/1.4 var(--font-mono);
    color: var(--text-faint); letter-spacing: var(--tracking-small);
    white-space: nowrap;
  }}
  .suggest {{
    margin-left: var(--space-2); padding: 0 var(--space-2);
    border: 1px solid var(--border-strong); border-radius: var(--radius-pill);
    background: var(--surface-raised); color: var(--text-muted); cursor: pointer;
    font: var(--fw-medium) var(--text-2xs)/1.6 var(--font-mono);
    text-transform: none; letter-spacing: 0;
  }}
  .suggest:hover {{ color: var(--text-strong); border-color: var(--brand); }}
  /* A box you type into, with the answers this appliance already holds one
     click away. The `<datalist>` is still there — typing filters it — but a
     datalist shows nothing until somebody types, so the offer was kept only
     for the operator who already knew it was there. The control says so. */
  .combo {{ position: relative; display: inline-flex; align-items: center; gap: var(--space-2); }}
  .combo > .caret {{
    flex: none; padding: var(--space-1) var(--space-2); line-height: 1;
    border: 1px solid var(--border-strong); border-radius: var(--radius-sm);
    background: var(--surface-raised); color: var(--text-muted); cursor: pointer;
    font: var(--fw-medium) var(--text-sm)/1 var(--font-mono);
  }}
  .combo > .caret:hover {{ color: var(--text-strong); border-color: var(--brand); }}
  .combo > .menu {{
    position: absolute; z-index: 5; top: calc(100% + var(--space-1)); left: 0;
    display: flex; flex-direction: column; min-width: 100%; padding: var(--space-1);
    border: 1px solid var(--border-strong); border-radius: var(--radius-sm);
    background: var(--surface-raised); box-shadow: var(--shadow-md);
  }}
  .combo .choice {{
    border: 0; background: none; cursor: pointer; text-align: left;
    padding: var(--space-1) var(--space-2); color: var(--text-body);
    font: var(--fw-regular) var(--text-sm)/1.6 var(--font-mono); white-space: nowrap;
  }}
  .combo .choice:hover {{ background: var(--surface-sunken); color: var(--text-strong); }}
  /* A list with its usual answers under it. The chips sit below the box rather
     than beside it because they are as long as the values they stand for, and
     a row of them squeezed into a column meant for one value wraps to three
     lines that look like a second field. Ticked and unticked are drawn the
     same way a `.pickone` is — the same gesture, so the same appearance. */
  .chips {{ display: flex; flex-direction: column; gap: var(--space-2); align-items: stretch; }}
  .chiprow {{ display: flex; flex-wrap: wrap; gap: var(--space-1); }}
  .chip {{
    padding: var(--space-1) var(--space-2);
    border: 1px solid var(--border); border-radius: var(--radius-sm);
    background: var(--surface-sunken); color: var(--text-muted); cursor: pointer;
    font: var(--fw-regular) var(--text-2xs)/1.5 var(--font-mono);
  }}
  .chip:hover {{ color: var(--text-body); border-color: var(--border-strong); }}
  .chip.on {{
    color: var(--text-strong); border-color: var(--brand);
    background: color-mix(in srgb, var(--brand) 10%, transparent);
  }}
  /* A time of day is a time of day: the platform's own control, sized to what
     it holds, so it does not read as a wide empty box somebody forgot. */
  input[type="time"] {{ font-variant-numeric: tabular-nums; }}
  /* One question asked about several things: the row says what, the column
     says which way, and the control in the cell is the answer. The headers do
     the labelling, so the field inside carries none — a label repeated down
     nine rows is the table's own first column said twice. */
  /* Sized to what it holds, not to the page: a route map name in a box six
     hundred pixels wide is the same mistake as a port in one, and the point of
     the table was to take up less room, not to spread the same sixteen
     controls across more of it. */
  .mtx {{ border-collapse: collapse; width: auto; }}
  .mtx th {{
    padding: var(--space-2) var(--space-3); text-align: left;
    color: var(--text-muted); font: var(--fw-medium) var(--text-xs)/1.4 var(--font-sans);
    letter-spacing: var(--tracking-body);
    border-bottom: 1px solid var(--border);
  }}
  .mtx td {{ padding: var(--space-2) var(--space-3); vertical-align: top; }}
  .mtx tbody tr + tr td, .mtx tbody tr + tr th {{ border-top: 1px solid var(--border); }}
  .mtx th.mtxrow {{
    white-space: nowrap; color: var(--text-body); text-transform: none;
    letter-spacing: normal; border-bottom: 0;
    font: var(--fw-regular) var(--text-sm)/1.6 var(--font-sans);
  }}
  .mtx td .field {{ margin: 0; }}
  .mtx td .field select, .mtx td .field input {{ width: 260px; max-width: 260px; }}
  .mtx td .sub {{ color: var(--text-faint); }}
  .req {{
    margin-left: var(--space-2); color: var(--product-strong);
    font: var(--fw-medium) var(--text-xs)/1.2 var(--font-sans);
    letter-spacing: var(--tracking-body);
  }}
  .formerr {{ grid-column: 1 / -1; margin: var(--space-2) 0 0; font-size: var(--text-sm); }}
  /* What the value means, under the value. Small and quiet: it is an aid, and
     an aid that competes with the field is a distraction. */
  .hint {{ font: var(--fw-regular) var(--text-2xs)/1.4 var(--font-mono);
    color: var(--text-faint); letter-spacing: var(--tracking-small);
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
    font: var(--fw-semibold) var(--text-xs)/1.35 var(--font-sans);
    letter-spacing: var(--tracking-body);
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
    border-left: 3px solid var(--border-strong);
  }}
  .ok {{ color: var(--status-up); }}

  dialog {{
    border: 1px solid var(--border-strong); border-radius: var(--radius-lg);
    background: var(--surface); color: var(--text-body);
    box-shadow: var(--shadow-lg); padding: var(--space-5) var(--space-6);
    max-width: 48rem; width: calc(100% - var(--space-7));
    /* A dialog is the one thing here that arrives rather than appears: it
       covers the page an operator was reading, and a full-screen surface that
       teleports in reads as a page change. It is also occasional — the answer
       to Apply, or the editor — so it can afford the two hundred milliseconds
       a rail control cannot. Opacity and transform only, no origin (a modal is
       not anchored to what opened it), and it leaves the way it came. */
    opacity: 0; transform: scale(.97);
    transition: opacity var(--dur-base) var(--ease-out),
                transform var(--dur-base) var(--ease-out),
                overlay var(--dur-base) allow-discrete,
                display var(--dur-base) allow-discrete;
  }}
  /* The rule editor holds a whole mask, and a mask is columns. At 48rem it got
     one of them and became a twenty-row questionnaire — the same object the add
     panel lays out four abreast. Wide enough for three, and no wider: a modal
     that fills the screen has stopped being a modal. */
  /* The editor is a drawer from the right edge, not a centred modal: the table
     it edits stays visible behind a light scrim, so the row being changed and
     the form changing it are on screen together. */
  dialog#editor {{
    position: fixed; inset: var(--bar-h) 0 0 auto; margin: 0;
    height: calc(100dvh - var(--bar-h)); max-height: none;
    width: min(46rem, 94vw); max-width: none;
    border: 0; border-left: 1px solid var(--border-strong); border-radius: 0;
    overflow-y: auto;
  }}
  /* The scrim stops where the drawer stops: the bar above stays readable and
     usable, so the pending-changes answer is never behind a veil. */
  dialog#editor::backdrop {{
    background: linear-gradient(to bottom,
      transparent 0, transparent var(--bar-h, 60px),
      rgba(0,0,0,.25) var(--bar-h, 60px));
  }}
  /* Add-forms are the same gesture: a panel that slides in at the right and
     leaves the list it extends readable. The inline edit rows inside tables
     (`.editrow .addpanel`) are exempt — they are the row itself. */
  .card.addpanel:not(.hidden) {{
    position: fixed; top: var(--bar-h); right: 0; bottom: 0; z-index: 15;
    width: min(44rem, 94vw); margin: 0; overflow-y: auto;
    border-radius: 0; border: 0; border-left: 1px solid var(--border-strong);
    box-shadow: var(--shadow-lg);
  }}
  dialog[open] {{ opacity: 1; transform: scale(1); }}
  @starting-style {{ dialog[open] {{ opacity: 0; transform: scale(.97); }} }}
  dialog::backdrop {{
    background: rgba(7,10,16,0);
    transition: background var(--dur-base) var(--ease-out),
                overlay var(--dur-base) allow-discrete,
                display var(--dur-base) allow-discrete;
  }}
  dialog[open]::backdrop {{ background: rgba(7,10,16,.7); }}
  @starting-style {{ dialog[open]::backdrop {{ background: rgba(7,10,16,0); }} }}

  /* The jump palette rides high rather than centred — it is a place to type,
     not a page to read, and a search box anchored near the top is where the
     hand expects it. Padding is nil on the shell so the input can own the top
     edge and the list can scroll under it. */
  dialog#palette {{ max-width: 40rem; margin: 12vh auto auto; padding: 0; overflow: hidden; }}
  #paletteq {{
    width: 100%; box-sizing: border-box; border: 0;
    border-bottom: 1px solid var(--border); background: transparent;
    color: var(--text-body); font: inherit; font-size: 1rem; outline: none;
    padding: var(--space-4) var(--space-5);
  }}
  #palettelist {{
    max-height: 50vh; overflow-y: auto; padding: var(--space-2);
    display: flex; flex-direction: column; gap: 2px;
  }}
  .palitem {{
    display: flex; align-items: baseline; justify-content: space-between;
    gap: var(--space-4); width: 100%; text-align: left; cursor: pointer;
    padding: var(--space-2) var(--space-3); border-radius: var(--radius-sm);
    border: 1px solid transparent; background: transparent; color: var(--text-body);
  }}
  .palitem:hover {{ background: var(--surface-hover); }}
  /* The keyboard's selection, and the one the pointer would land on, are the
     same highlight — arrowing down and hovering are one idea to the operator. */
  .palitem.on {{ background: var(--surface-hover); border-color: var(--border-strong); }}
  .palt {{ font-weight: 500; }}
  .palg {{ color: var(--text-muted); font-size: .82rem; white-space: nowrap; }}
  .palempty {{ color: var(--text-muted); padding: var(--space-3); }}
  /* The hint that the palette exists, sat under the rail's own search. Quiet by
     default — an operator who needs it will find it, and one who does not is not
     asked to read it every time. */
  .palhint {{
    display: flex; align-items: center; justify-content: space-between;
    gap: var(--space-2); width: 100%; cursor: pointer;
    margin-top: var(--space-2); padding: var(--space-2) var(--space-3);
    border: 1px solid var(--border-subtle); border-radius: var(--radius-sm);
    background: transparent; color: var(--text-muted); font: inherit; font-size: .82rem;
  }}
  .palhint:hover {{ background: var(--surface-hover); color: var(--text-body); }}
  .palhint kbd {{
    font: inherit; font-size: .74rem; padding: 1px var(--space-2);
    border: 1px solid var(--border); border-radius: var(--radius-xs);
    background: var(--surface-sunken); color: var(--text-muted);
  }}
  .script {{
    background: var(--surface-sunken); border: 1px solid var(--border);
    border-radius: var(--radius-sm);
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
    letter-spacing: var(--tracking-tight); color: var(--text-strong);
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

  /* Category icons are quiet: colour in the rail belongs to the accent that
     marks where you are, and to nothing else. Twelve tinted icons were a paint
     chart, and the tints took meaning away from the status colours. */
  aside button.navitem.cat {{ padding-block: var(--space-2); }}
  aside button.navitem.cat svg {{ color: var(--cat, var(--text-muted)); width: 17px; height: 17px; }}
  aside button.navitem.cat.on {{ color: var(--text-strong); background: var(--surface-raised); }}
  aside button.navitem.cat.on::before {{ background: var(--cat, var(--brand)); }}
  aside button.navitem.cat:hover svg {{ filter: brightness(1.25); }}

  /* The pages inside the category, in the content rather than the rail. It sits
     above the heading because it is what the heading is one of.

     This is the only navigation a page carries. A divided view — routing, with
     a pane per protocol — used to print its panes a second time in a strip of
     its own directly underneath, which is two rows of buttons for one decision
     and no way to tell which of them you are standing in. The panes are pages
     of the category like any other, so they are listed here, once, with the
     marks that used to justify the second row: an icon per page and a dot on
     the ones that already carry configuration. */
  .secstrip {{
    display: flex; flex-wrap: wrap; gap: var(--space-1);
    padding: 0 var(--space-6); margin-bottom: var(--space-2);
  }}
  .secstrip:empty {{ display: none; }}
  .secstrip .secitem {{
    display: inline-flex; align-items: center; gap: var(--space-2);
    background: none; border: 0; border-bottom: 2px solid transparent;
    padding: var(--space-2) var(--space-3); cursor: pointer;
    font: var(--fw-medium) var(--text-sm)/1.2 var(--font-sans); color: var(--text-muted);
  }}
  .secstrip .secitem svg {{ width: 14px; height: 14px; flex: none; opacity: .8; }}
  .secstrip .secitem:hover {{ color: var(--text-strong); }}
  .secstrip .secitem.on {{ color: var(--text-strong); border-bottom-color: var(--cat, var(--brand)); }}
  /* Configured is not a status, and a mark that borrowed the colour of "up"
     would tell an operator something the appliance never said. */
  .secstrip .secitem .live {{
    width: 5px; height: 5px; border-radius: 50%;
    background: var(--text-faint); flex: none;
  }}

  /* The dashboard's top row. A tile is a number and what it counts; the colour
     is the same one its category carries in the rail, so the eye can follow a
     tile to the page that explains it. */
  /* The same tracks as .cards above it: two tile bands whose columns do not
     line up read as two unrelated pages sharing a scroll position. */
  /* One structured strip, not a row of cards: the figures share one border and
     are divided by vertical rules, so the page opens with a single quiet
     instrument panel instead of five competing tiles. */
  .stats {{
    display: flex; flex-wrap: wrap; margin-bottom: var(--space-4);
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius-lg); overflow: hidden;
  }}
  .stat {{
    display: flex; flex-direction: column; gap: 2px; flex: 1 1 11rem;
    padding: var(--space-3) var(--space-4);
    border-right: 1px solid var(--border-subtle);
  }}
  .stat:last-child {{ border-right: 0; }}
  .stat .slabel {{
    font: var(--fw-medium) var(--text-xs)/1.2 var(--font-sans);
    letter-spacing: var(--tracking-body); color: var(--text-muted);
  }}
  .stat .svalue {{
    font: var(--fw-semibold) var(--text-lg)/1.2 var(--font-mono);
    color: var(--text-strong); font-variant-numeric: tabular-nums;
  }}
  .stat .sfoot {{ font: var(--text-xs)/1.3 var(--font-sans); color: var(--text-faint); }}

  /* Two cards side by side where there is room, stacked where there is not. */
  /* Eine Zeile einer Befehlsausgabe, nicht eine Zahl: linksbündig, monospace
     und ohne Umbruch -- die Karte scrollt, statt die Zeile zu zerlegen. */
  td.line {{
    font: var(--text-xs)/1.5 var(--font-mono); color: var(--text-muted);
    white-space: pre; text-align: left;
  }}
  .dashgrid {{
    display: grid; gap: var(--space-3); margin-bottom: var(--space-4);
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
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
    font: var(--fw-medium) var(--text-xs)/1.6 var(--font-sans);
    letter-spacing: var(--tracking-body);
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
  .pill.warn {{ color: var(--amber-300); }}
  .pill.warn::before {{ background: var(--status-warn); }}
  /* The header's staged-changes indicator is the single global answer to "am I
     editing live state?" — the one status on the page that earns a frame. It is
     also the way back to the review, so it behaves like a control. */
  #stagedbadge.warn {{
    padding: 3px var(--space-3); border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--status-warn) 9%, transparent);
    border: 1px solid color-mix(in srgb, var(--status-warn) 42%, transparent);
    cursor: pointer;
  }}
  #stagedbadge.warn:hover {{
    background: color-mix(in srgb, var(--status-warn) 14%, transparent);
  }}
  .userchip {{
    display: inline-flex; align-items: center; gap: var(--space-2);
    color: var(--text-muted); font-size: var(--text-sm); white-space: nowrap;
  }}
  .userchip .init {{
    display: inline-flex; align-items: center; justify-content: center;
    width: 26px; height: 26px; border-radius: var(--radius-sm);
    border: 1px solid var(--border); background: var(--surface-raised);
    font: var(--fw-semibold) var(--text-2xs)/1 var(--font-sans);
    color: var(--text-body); letter-spacing: .02em;
  }}
  .dot.warn {{ background: var(--status-warn); box-shadow: 0 0 8px -1px var(--status-warn); }}
  .change {{
    display: flex; align-items: center; gap: var(--space-3);
    padding: var(--space-2) 0; border-bottom: 1px solid var(--border-subtle);
  }}
  .change:last-child {{ border-bottom: 0; }}
  .change .what {{ flex: 1 1 auto; font-size: var(--text-sm); color: var(--text-body); }}
  #stagedlist {{ background: none; border: 0; border-left: 0; padding: 0; white-space: normal; }}

  /* --- rail groups --------------------------------------------------------
     Collapsible, because Routing alone is eleven entries once every protocol
     is listed, and a rail you have to scroll past is one you stop reading. */
  /* Group heads are the signs on a directory board: ruled off, so the eye can
     take the rail in as five short lists rather than as sixty lines. */
  nav .grouphead {{
    display: flex; align-items: center; gap: var(--space-2); width: 100%;
    background: none; cursor: pointer; color: var(--text-faint);
    font: var(--fw-semibold) var(--text-xs)/1.2 var(--font-sans);
    letter-spacing: var(--tracking-body);
    padding: var(--space-3) var(--space-3) var(--space-2);
    margin: var(--space-4) 0 var(--space-1);
    border: 0; border-bottom: 1px solid var(--border-subtle);
  }}
  nav .grouphead:hover {{ color: var(--text-muted); }}
  nav .grouphead svg {{
    width: 12px; height: 12px; margin-left: auto;
    /* The chevron turns where it stands, which is movement on screen rather
       than an entrance — and it is a rail control, so it stays under the
       imperceptible mark. */
    transition: transform var(--dur-fast) var(--ease-in-out);
  }}
  nav .group.closed .grouphead svg {{ transform: rotate(-90deg); }}
  nav .group.closed .navitem {{ display: none; }}

  /* --- dashboard tiles ---------------------------------------------------- */
  .kpi {{
    display: flex; flex-direction: column; gap: var(--space-1);
    border: 1px solid var(--border); border-radius: var(--radius-lg);
    background: var(--surface);
    padding: var(--space-4) var(--space-5);
    transition: border-color var(--dur-fast) ease;
  }}
  .kpi:hover {{ border-color: var(--border-strong); }}
  .kpi .klabel {{
    font: var(--fw-semibold) var(--text-xs)/1.2 var(--font-sans);
    letter-spacing: var(--tracking-body);
    color: var(--text-muted);
  }}
  .kpi .kfoot {{ font-size: var(--text-xs); color: var(--text-faint); }}
  /* State at conversation volume. The dot and the word carry the code —
     red still means down — but a display-size "inactive" made an expected
     state the loudest thing on the page, and a page that shouts its normal
     state has nothing left for an abnormal one. */
  .kpi .metric {{
    font-size: var(--text-lg); font-weight: var(--fw-medium);
    letter-spacing: var(--tracking-tight);
  }}

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
    /* A band earns its height from its fields, not from its chrome: 2rem of
       lead over a group holding one control was more heading than mask. */
    padding: var(--space-5) 0 var(--space-4);
    margin: 0;
  }}
  .spread.first {{ border-top: 0; padding-top: var(--space-2); }}
  .spread > * {{ grid-column: 2; min-width: 0; }}
  .spread > .margin {{ grid-column: 1; }}
  .margin {{ min-width: 0; padding-top: 2px; }}
  .margin > h3 {{
    display: block; margin: 0;
    font: var(--fw-semibold) var(--text-xs)/1.35 var(--font-sans);
    letter-spacing: var(--tracking-body);
    color: var(--text-muted);
    padding-bottom: var(--space-2);
    border-bottom: 1px solid var(--border);
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
  /* …and where there is no margin column to keep the edge of — inside a modal,
     which has its own edges and no room for a 208px one — the headings go back
     above what they name and nothing is indented. `inset` would have done half
     of this and pushed the whole mask sideways doing it. */
  .flush .spread {{ grid-template-columns: minmax(0, 1fr); }}
  .flush .spread > * {{ grid-column: 1; }}
  .flush .spread > .margin {{ margin-bottom: var(--space-3); }}
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
  /* overflow-y hidden as well: `auto` on one axis drags a vertical stub
     along on some platforms, and a table never needs to scroll inside its
     own card vertically — the page does that. */
  .tblwrap {{ overflow-x: auto; overflow-y: hidden; }}
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
  /* Row actions are furniture, not content. Forty rules meant eighty framed
     buttons — a wall of chrome beside three columns of information. At rest
     they are words; the frame appears under the pointer, where it means
     something. Focus keeps its ring, so the keyboard loses nothing. */
  table.otbl td.end .btn {{
    background: transparent; border-color: transparent; color: var(--text-muted);
  }}
  table.otbl td.end .btn:hover {{
    background: var(--surface-hover); border-color: var(--border);
    color: var(--text-strong);
  }}
  table.otbl td.end .btn:focus-visible {{ border-color: var(--brand); }}
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
  /* A switch is as wide as a switch. It sits in the column it was given and
     stops there, rather than stretching a two-state control across a track
     sized for an address. */
  .field.w-auto > .switch {{ align-self: start; }}

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
  .inset .maskfoot, .spread .maskfoot, .flush .maskfoot,
  .inset .formerr, .spread .formerr, .flush .formerr {{ margin-left: 0; }}
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

  /* Reduced motion means fewer and gentler, not none. What is dropped is
     movement — the chevron's rotation, the dialog's scale — while the fades
     that tell an operator a surface arrived are kept, and kept short. Turning
     every transition off wholesale takes away the explanation along with the
     motion. */
  @media (prefers-reduced-motion: reduce) {{
    nav .grouphead svg {{ transition: none; }}
    /* The knob still changes side — that is the state, not decoration — but it
       stops sliding there. The colour still moves, because that is what says
       the switch took the press. */
    .knob::after {{ transition: background var(--dur-fast) ease; }}
    dialog {{
      transform: none;
      transition: opacity var(--dur-fast) ease,
                  overlay var(--dur-fast) allow-discrete,
                  display var(--dur-fast) allow-discrete;
    }}
    dialog[open] {{ transform: none; }}
    @starting-style {{ dialog[open] {{ transform: none; }} }}
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
    <button id="palettehint" class="palhint" type="button"
            aria-keyshortcuts="Meta+K Control+K">
      <span>Jump to a page</span><kbd>⌘K</kbd>
    </button>

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
      <!-- Who is driving. The identity sits where every console in the family
           puts it — top right — so the answer to "am I the right account for
           this?" never needs a trip to the sidebar. -->
      <span class="userchip" id="userchip">
        <span class="init" id="whoinit">MT</span>
        <span class="uname" id="whoname">management token</span>
      </span>
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

    <div class="secstrip" id="sectionstrip"></div>
    <div class="page" id="pagehead"></div>

    <div id="view-dashboard">
      <!-- What the box is, in numbers, before any chart. An operator opening a
           router console wants to know the size of the thing they are looking
           at -- how many links, how many routes, how many rules -- and a page
           that opens with a time series answers a question they have not asked
           yet. -->
      <div class="stats" id="stats"></div>
      <div class="cards" id="services"></div>
      <div class="dashgrid">
        <div class="card">
          <h3>Interfaces</h3>
          <div class="tblwrap"><table id="dashlinks"></table></div>
        </div>
        <div class="card">
          <h3>System</h3>
          <table id="dashsystem"></table>
        </div>
      </div>
      <div class="cards" id="graphs"></div>
      <div class="dashgrid">
        <div class="card">
          <h3>Routes</h3>
          <div class="tblwrap"><table id="dashroutes"></table></div>
        </div>
        <div class="card">
          <h3>Rules carrying traffic</h3>
          <div class="tblwrap"><table id="dashrules"></table></div>
        </div>
      </div>
      <div class="card">
        <h3>Recent log</h3>
        <div class="tblwrap"><pre class="out" id="dashlog"></pre></div>
      </div>
      <div class="card">
        <h3>Counters</h3>
        <label class="check">
          <input type="checkbox" id="allcounters">
          <span>Show counters that are still zero</span>
        </label>
        <div class="tblwrap"><table id="counters"></table></div>
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

      <div class="section">
        <h3>Zones</h3>
        <span class="spacer"></span>
        <button class="btn" id="togglezone">New zone</button>
      </div>
      <div class="card addpanel hidden" id="addzonepanel"></div>
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
            <option value="interface-group">links</option>
            <option value="mac-group">hardware addresses</option>
            <option value="feed-group">published list</option>
            <option value="user-group">VPN users</option>
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
        <button class="btn" id="toggleradius">New RADIUS server</button>
      </div>
      <div class="card addpanel hidden" id="addradiuspanel"></div>
      <div id="radiuslist"></div>

      <div class="section">
        <h3>Directories (LDAP)</h3>
        <span class="spacer"></span>
        <button class="btn" id="toggleldap">New directory</button>
      </div>
      <p class="lede inset" style="margin:0 0 var(--space-4)">
        A simple bind as the user, so what is needed is where the accounts live
        and what names one. There is no service account here on purpose:
        searching first would mean a second password living on the firewall.
      </p>
      <div class="card addpanel hidden" id="addldappanel"></div>
      <div id="ldaplist"></div>

      <div class="section">
        <h3>TACACS+ servers</h3>
        <span class="spacer"></span>
        <button class="btn" id="toggletacacs">New TACACS+ server</button>
      </div>
      <div class="card addpanel hidden" id="addtacacspanel"></div>
      <div id="tacacslist"></div>

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
      <div class="card">
        <h3>What is watched, and what a hit costs</h3>
        <p class="lede" style="margin:0 0 var(--space-4)">
          A detector with no rules detects nothing, so a ruleset or a rule is
          required before the links mean anything. Blocking on an alert is the
          setting worth thinking twice about: name your own way in under
          <em>never block</em> first, or an alert on the management network takes
          it away.
        </p>
        <div class="grid" id="svc-ids"></div>
      </div>
      <div class="card"><h3>Detector</h3><pre class="out" id="idsshow">…</pre></div>
      <div class="card"><h3>Recent alerts</h3><pre class="out" id="alertshow">…</pre></div>
    </div>

    <div id="view-evpn" class="hidden">
      <div class="card">
        <h3>This box</h3>
        <p class="lede" style="margin:0 0 var(--space-4)">
          The tunnel endpoint address is the outer source of everything this box
          encapsulates and the next hop it announces itself under. VXLAN is what
          every switch speaks; Geneve carries options VXLAN cannot and costs
          eight more bytes per packet.
        </p>
        <div class="grid" id="evpnform"></div>
      </div>
      <div class="section">
        <h3>Segments</h3>
        <span class="spacer"></span>
        <button class="btn" id="toggleevi">New</button>
      </div>
      <p class="lede">
        A layer-2 segment and the local ports on it. The VNI is the segment's id
        on the wire and the data plane's id for it, so two segments cannot share
        one.
      </p>
      <div class="card addpanel hidden" id="addevipanel"></div>
      <div id="evilist"></div>
      <div class="section">
        <h3>Tenants</h3>
        <span class="spacer"></span>
        <button class="btn" id="toggleipvrf">New</button>
      </div>
      <p class="lede">
        Routing <em>between</em> segments, for a tenant with more than one
        subnet. Each names a VRF that has to exist under routing.
      </p>
      <div class="card addpanel hidden" id="addipvrfpanel"></div>
      <div id="ipvrflist"></div>
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

      <div class="tabpane hidden" data-tab="prefix">
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
          URL, the trust is the key. Name a channel below to run several side
          by side; the active one is chosen here.
        </p>
        <div class="grid" id="sys-update"></div>
      </div>
      <div class="section">
        <h3>Update channels</h3>
        <span class="spacer"></span>
        <button class="btn" id="toggleupchan">New channel</button>
      </div>
      <p class="lede inset" style="margin:0 0 var(--space-4)">
        Each channel is signed by its own key, so trusting one channel pins one
        key. A subscription key buys tested, delayed-stability images — never
        features — and if it expires the appliance keeps running unchanged:
        only new images from that channel become unavailable.
      </p>
      <div class="card addpanel hidden" id="addupchanpanel"></div>
      <div id="upchanlist"></div>
      <div class="card"><h3>Subscription</h3><pre class="out" id="subshow">…</pre></div>
      <div class="card"><h3>Version</h3><pre class="out" id="sysshow">…</pre></div>
    </div>

    <!-- Interior routing. One view, one tab per protocol: an appliance that
         speaks seven of them must not stack seven forms on one scroll, and the
         rail lists the same seven so either way in lands on the same page. -->
    <div id="view-routing" class="hidden">

      <div class="tabpane hidden" data-tab="static">
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
        <div class="card"><div class="grid" id="bgpglobal"></div></div>
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
        <div class="card"><div class="grid" id="igp-ospf"></div></div>
        <div class="card"><h3>Neighbours</h3><pre class="out" id="show-ospf">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="ospf3">
        <div class="card"><div class="grid" id="igp-ospf3"></div></div>
        <div class="card"><h3>Neighbours</h3><pre class="out" id="show-ospf3">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="isis">
        <div class="card"><div class="grid" id="igp-isis"></div></div>
        <div class="card"><h3>Adjacencies</h3><pre class="out" id="show-isis">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="rip">
        <div class="card"><div class="grid" id="igp-rip"></div></div>
        <div class="card"><h3>State</h3><pre class="out" id="show-rip">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="ripng">
        <div class="card"><div class="grid" id="igp-ripng"></div></div>
        <div class="card"><h3>State</h3><pre class="out" id="show-ripng">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="babel">
        <div class="card"><div class="grid" id="igp-babel"></div></div>
        <div class="card"><h3>State</h3><pre class="out" id="show-babel">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="bfd">
        <div class="card"><div class="grid" id="igp-bfd"></div></div>
        <div class="card"><h3>Sessions</h3><pre class="out" id="show-bfd">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="multicast">
        <div class="card"><div class="grid" id="mcastform"></div></div>
        <p class="lede inset" style="margin:0 0 var(--space-4)">
          The querier carries multicast <em>within</em> a segment; PIM routes it
          <em>between</em> them. Every join is sent toward the rendezvous point
          until somebody learns who the source is, which is why sparse mode has
          no meaning without an RP address — and each link PIM speaks on must
          also be a multicast interface below.
        </p>
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
        <div class="section">
          <h3>Instances</h3>
          <span class="spacer"></span>
          <button class="btn" id="togglevrf">New VRF</button>
        </div>
        <div class="card addpanel hidden" id="addvrfpanel"></div>
        <div id="vrflist"></div>
        <div class="card"><h3>Instances</h3><pre class="out" id="show-vrf">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="filters">
        <div class="card"><div class="grid" id="redistfilters"></div></div>
        <!-- What these settings decide, read back: the table is the outcome of
             what was let in. Same command as the Routing table tab, which is
             the point — that tab asks what the box knows, this one asks what
             these filters did to it. -->
        <div class="card"><h3>Live state</h3><pre class="out" id="filtershow">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="table">
        <div class="card"><h3>Routing table</h3><pre class="out" id="igpshow">…</pre></div>
      </div>
    </div>

    <!-- Fourteen services on one scroll was a list, not a page. They group the
         way an operator thinks about them: what answers questions, what lets
         you in, what hands out addresses, what publishes, what tells you. -->
    <div id="view-services" class="hidden">

      <div class="tabpane hidden" data-tab="resolution">
        <div class="card"><h3>DNS resolver</h3><div class="grid" id="svc-dns"></div></div>
        <div class="card"><h3>NTP</h3><div class="grid" id="svc-ntp"></div></div>
      </div>

      <div class="tabpane hidden" data-tab="management">
        <div class="card"><h3>SSH access</h3><div class="grid" id="svc-ssh"></div></div>
        <div class="card"><h3>Web console</h3><div class="grid" id="svc-web"></div></div>
        <div class="card"><h3>SNMP (read-only)</h3><div class="grid" id="svc-snmp"></div></div>
        <div class="card"><h3>LLDP</h3><div class="grid" id="svc-lldp"></div></div>
      </div>

      <div class="tabpane hidden" data-tab="addressing">
        <div class="card"><h3>DHCP relay</h3><div class="grid" id="svc-dhcprelay"></div></div>
        <div class="card"><h3>PPPoE server</h3><div class="grid" id="svc-pppoeserver"></div></div>
        <div class="section">
          <h3>PPPoE subscribers</h3>
          <span class="spacer"></span>
          <button class="btn" id="togglepppoeuser">New subscriber</button>
        </div>
        <div class="card addpanel hidden" id="addpppoeuserpanel"></div>
        <div id="pppoeusers"></div>
        <div class="card"><h3>Dynamic DNS</h3><div class="grid" id="svc-dyndns"></div></div>
        <div class="card"><h3>mDNS reflector</h3><div class="grid" id="svc-mdns"></div></div>
      </div>

      <div class="tabpane hidden" data-tab="publishing">
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
        <div class="card">
          <h3>Alerts</h3>
          <p class="lede" style="margin-bottom:var(--space-4)">
            Webhooks are a space-separated list; the mail relay below is optional.
          </p>
          <div class="grid" id="svc-alerts"></div>
        </div>
        <div class="card"><h3>Alert mail</h3><div class="grid" id="svc-alertmail"></div></div>
        <div class="card">
          <h3>Flow export (IPFIX)</h3>
          <p class="lede" style="margin:0 0 var(--space-4)">
            Every connection this box tracks, shipped to a collector as RFC 7011
            records. What is sent is the change since the last export, not a
            running total — a collector sums what it receives.
          </p>
          <div class="grid" id="svc-flow"></div>
        </div>

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
        <!-- Both are bounded by the appliance, so the boxes are bounded too:
             the arrow keys step through the range and 600 seconds cannot be
             typed into a field the capture would refuse. -->
        <label class="field w-s"><span>Packets</span>
          <input id="cap-count" type="number" inputmode="numeric" min="1" max="500" value="50">
        </label>
        <label class="field w-s"><span>Seconds</span>
          <span class="num">
            <input id="cap-secs" type="number" inputmode="numeric" min="1" max="60" value="10">
            <span class="unit">s</span>
          </span>
        </label>
        <button class="btn primary" id="runcapture">Capture</button>
      </div>
      <div class="card"><h3>Output</h3><pre class="out" id="capout">Not run yet.</pre></div>
    </div>

    <div id="view-config" class="hidden">
      <div class="card">
        <h3>Revisions</h3>
        <p class="lede" style="margin:0 0 var(--space-3)">
          Every save archives a revision. Rolling back stages the change like any
          other, so it lands only when you apply it.
        </p>
        <div class="tblwrap"><table id="revtable"></table></div>
      </div>
    </div>

    <div id="view-stack" class="hidden">
      <div class="card">
        <h3>Members</h3>
        <div class="tblwrap"><table id="stacktable"></table></div>
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
  <!-- The same markup every field in a mask has, because this one now sits in
       one: a `.field` whose label is a `<span>`. It was a `<div>` with a
       `<label for>` beside it, and anything walking the mask's fields for their
       names — the browser suite does — found a field with no name in it. -->
  <label class="field w-m" id="r-namefield"><span>Name</span><input id="r-name"></label>
  <!-- `flush`, because a modal has no margin column: the group headings go
       back above what they name, and nothing is pushed sideways to line up
       with a gutter that is not there. -->
  <div class="flush" id="editorfields"></div>
  <p id="editorerr" class="err"></p>
  <div class="row" style="margin-top:.9rem">
    <button class="btn primary" id="applysave">Stage</button>
    <button class="btn" id="cancel">Cancel</button>
    <!-- The same "More settings" control the add panel carries, placed by
         `openEditor`. Emptied and refilled each open so a second edit does not
         inherit the first rule's button. -->
    <span id="editormore"></span>
  </div>
</dialog>

<dialog id="result">
  <h3 style="margin:0 0 var(--space-4)" id="resulttitle">Applied</h3>
  <div id="resultout"></div>
  <div class="row" style="margin-top:.9rem"><button class="btn" id="resultclose">Close</button></div>
</dialog>

<!-- The jump palette. Sixty-nine pages behind a rail of categories is two
     clicks to anywhere and a guess at which category holds what you want; this
     is the way in for an operator who knows the page's name and not its box.
     One flat, searchable list of every editable view and every live panel,
     opened with Cmd/Ctrl-K, driven by the arrows and Enter, closed with Esc.
     It reuses the rail's own activation — `goto` for a view, the panel swap for
     a look — so there is one code path to a page however you reach it. -->
<dialog id="palette" aria-label="Jump to a page">
  <input id="paletteq" placeholder="Jump to a page…" autocomplete="off"
         role="combobox" aria-controls="palettelist" aria-expanded="true">
  <div id="palettelist" role="listbox" aria-label="Pages"></div>
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
// Re-runs the write gate whenever the page redraws a list: the lists rebuild
// themselves constantly, and a gate that ran once per view left every row's
// Edit and Delete enabled for a read-only account.
let gateObserver = null;
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
  const accent = css.getPropertyValue("--brand").trim() || "#2e96c4";
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

// The dashboard's top row: the size of the box, from what the appliance already
// answers. Each tile is one question an operator asks before anything else --
// how many links are up, how many routes are held, how many rules are written,
// how many flows are open. They are counted from the same `show` output the
// pages below use, so a tile can never disagree with the page it summarises.
function statTile(label, value, foot, colour) {{
  const t = el("div", {{ class: "stat" }});
  t.style.setProperty("--cat", colour);
  t.append(
    el("span", {{ class: "slabel", text: label }}),
    el("span", {{ class: "svalue", text: value }}),
    el("span", {{ class: "sfoot", text: foot || "" }}),
  );
  return t;
}}

// `ip -br`-style output: name, state, then addresses. Parsed rather than shown
// raw because the dashboard is a summary -- the raw form is one click away
// under Network, and duplicating it here would make two places to read.
function parseLinks(out) {{
  const links = [];
  for (const line of (out || "").split("\n")) {{
    const f = line.trim().split(/\s+/);
    if (f.length < 2 || f[0] === "lo") continue;
    const [name, state, ...addrs] = f;
    if (!/^(UP|DOWN|UNKNOWN)$/.test(state)) continue;
    links.push({{ name, state, addrs: addrs.filter((a) => a.includes("/") && !a.startsWith("fe80")) }});
  }}
  return links;
}}

async function refreshDashboardExtras() {{
  const stats = $("stats");
  const tiles = [];

  // Links.
  let links = [];
  try {{ links = parseLinks(await text("/api/v1/show/interfaces")); }} catch (e) {{}}
  const up = links.filter((l) => l.state === "UP").length;
  if (links.length) {{
    tiles.push(statTile("Interfaces", String(links.length),
      up + " up / " + (links.length - up) + " down", "#38bdf8"));
  }}
  const lt = $("dashlinks");
  lt.textContent = "";
  if (links.length) {{
    lt.append(el("tr", {{}}, [
      el("th", {{ text: "Interface" }}), el("th", {{ text: "State" }}), el("th", {{ text: "Address" }}),
    ]));
    for (const l of links.slice(0, 8)) {{
      lt.append(el("tr", {{}}, [
        el("td", {{ text: l.name }}),
        el("td", {{}}, [el("span", {{ class: "pill " + (l.state === "UP" ? "ok" : "warn"), text: l.state }})]),
        // One address per line. Joined with spaces they wrap mid-token at
        // whatever width the column happens to have, and a v6 address broken
        // inside a hex group cannot be read back or compared.
        el("td", {{ class: "val lines", text: l.addrs.join("\n") || "—" }}),
      ]));
    }}
  }}

  // Routes.
  let routes = [];
  try {{
    routes = (await text("/api/v1/show/ip/route")).split("\n").filter((l) => l.trim());
  }} catch (e) {{}}
  if (routes.length) tiles.push(statTile("Routes", String(routes.length), "in the kernel", "#a78bfa"));
  const rt = $("dashroutes");
  rt.textContent = "";
  for (const line of routes.slice(0, 8)) rt.append(el("tr", {{}}, [el("td", {{ class: "line", text: line }})]));
  if (!routes.length) rt.append(el("tr", {{}}, [el("td", {{ text: "No routes yet." }})]));

  // Rules, and which of them are carrying anything.
  try {{
    const fw = await text("/api/v1/show/firewall");
    const m = fw.match(/rules \((\d+)\)/);
    if (m) tiles.push(statTile("Firewall rules", m[1], "written", "#f59e0b"));
  }} catch (e) {{}}
  const rr = $("dashrules");
  rr.textContent = "";
  try {{
    const hits = (await text("/api/v1/show/firewall/hits")).split("\n").filter((l) => l.trim());
    for (const line of hits.slice(0, 9)) rr.append(el("tr", {{}}, [el("td", {{ class: "line", text: line }})]));
  }} catch (e) {{
    // A rule-hit table needs the agent's socket; saying so beats an empty box.
    rr.append(el("tr", {{}}, [el("td", {{ text: "The data plane did not answer: " + (e.message || e) }})]));
  }}

  // Open flows.
  try {{
    const flows = await text("/api/v1/show/firewall/flows");
    const m = flows.match(/(\d+)\s+flow/);
    if (m) tiles.push(statTile("Connections", m[1], "tracked right now", "#34d399"));
  }} catch (e) {{}}

  stats.textContent = "";
  for (const t of tiles) stats.append(t);

  // What the box itself is.
  const sys = $("dashsystem");
  sys.textContent = "";
  try {{
    const v = await text("/api/v1/show/version");
    // Every line the appliance reports, not a fixed count of them: `show
    // version` decides what identifies this box, and a console that keeps the
    // first six silently drops the seventh the day somebody adds one. It cost
    // exactly that — the data-at-rest line was invisible here for a release.
    for (const line of v.split("\n").filter((l) => l.trim())) {{
      const [k, ...rest] = line.split(/:\s+/);
      sys.append(el("tr", {{}}, [el("td", {{ text: k }}), el("td", {{ class: "val", text: rest.join(": ") }})]));
    }}
  }} catch (e) {{}}

  // The last thing that happened, so the page ends with news rather than a table.
  try {{
    const log = await text("/api/v1/show/firewall/log");
    $("dashlog").textContent = log.split("\n").slice(-12).join("\n") || "Nothing logged yet.";
  }} catch (e) {{ $("dashlog").textContent = "The log could not be read: " + (e.message || e); }}
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

  // The tiles and tables above the graphs, each from its own `show`.
  // Not awaited: the tiles come from six separate `show` calls and the graphs
  // below must not wait on the slowest of them. A rejection here would
  // otherwise be an unhandled one -- a dashboard that quietly stops filling in.
  refreshDashboardExtras().catch((e) => {{
    $("stats").textContent = "";
    $("stats").append(el("div", {{ class: "card", text: "The summary could not be read: " + (e.message || e) }}));
  }});

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
    // The strong line is whichever half constrains something. A rule that
    // names addresses or groups is audited by them, so they lead and the
    // zones follow underneath. But most rules constrain only zones — and for
    // those the old order put "any → any" in bold with the entire meaning of
    // the rule (wan → lan · tcp/443) in the fine print. A line that restates
    // the default earns no place at all, let alone the lead.
    el("td", {{}}, (source === "any" && dest === "any")
      ? [
          el("span", {{ class: "val", text: (r.from || "any") + " → " + (r.to || "any") +
            (r.proto ? " · " + r.proto + "/" + ports : "") }}),
        ]
      : [
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
//
// Grouped like every other mask on this appliance, and for the same reason:
// twenty boxes in one run under no heading is a form an operator fills in from
// the top rather than a rule they are writing. The order is the order the
// sentence goes in — what it does, what it matches, when it is open, how much
// it lets through, and what it is called.
const RULE_DAYS = [
  {{ value: "mon", label: "Mon" }}, {{ value: "tue", label: "Tue" }},
  {{ value: "wed", label: "Wed" }}, {{ value: "thu", label: "Thu" }},
  {{ value: "fri", label: "Fri" }}, {{ value: "sat", label: "Sat" }},
  {{ value: "sun", label: "Sun" }},
];
function ruleFields(zones) {{
  const zoneOpts = ["", ...zones];
  return [
    ["from", "From zone", zoneOpts],
    ["to", "To zone", zoneOpts],
    ["action", "Action", ["accept", "drop", "reject"]],
    ["#", "What it matches"],
    ["proto", "Protocol",
     ["", "tcp", "udp", "tcp_udp", "icmp", "icmpv6", "vrrp", "esp", "ah", "gre", "ospf", "pim"]],
    ["port", "Port"],
    ["port-group", "Port group"],
    // Both families' names, since which numbering applies follows from the
    // protocol above. A number is accepted too.
    ["icmp-type", "ICMP type", ["", "echo-request", "echo-reply",
      "destination-unreachable", "packet-too-big", "time-exceeded",
      "parameter-problem", "redirect", "router-solicitation",
      "router-advertisement", "neighbor-solicitation", "neighbor-advertisement"]],
    ["source", "Source"],
    ["source-group", "Source group"],
    ["destination", "Destination"],
    ["destination-group", "Destination group"],
    // Each of these names a *group*, not the thing itself: the appliance takes
    // `firewall group mac-group <name>` here and refuses a MAC, and the same
    // for the links — which is why neither is a set of tick boxes over this
    // box's interfaces however much the label sounds like one.
    ["source-mac-group", "Sender MAC group"],
    ["interface-group", "Only on these links"],
    // A rule with no address applies to both families; this is how it says
    // otherwise. `out` covers traffic this box originates, and is IPv4 only.
    ["family", "Address family", ["", "ipv4", "ipv6"]],
    ["direction", "Direction", ["", "in", "out"]],
    // The schedule is three leaves under one word, and `set … schedule days …`
    // is exactly the command the CLI takes. `pick` rather than `list`: the
    // appliance *assigns* the days, so the line that writes them must not be
    // preceded by a delete — see [`fieldLines`].
    ["#", "When it is open"],
    ["schedule days", "Open on days", RULE_DAYS, "pick"],
    ["schedule start", "Opens at"],
    ["schedule end", "Closes at"],
    ["#", "How much it lets through"],
    ["limit", "New flows"],
    ["burst", "Burst"],
    ["#", "What it is called, and whether it is on"],
    ["log", "Log matches", ["", "true", "false"]],
    ["disabled", "Disabled", ["", "true", "false"]],
    ["description", "Description"],
  ];
}}

// What a rule asks for depends on the protocol, because the appliance does. A
// port on a protocol that carries none is refused — "icmp carries no ports" —
// an ICMP type "needs protocol icmp or icmpv6", and a rate limit or a schedule
// "is only valid on a port rule". Offering all of it against every protocol is
// how a rule form asks for a rule nobody could commit.
const PORTED = ["tcp", "udp", "tcp_udp"];
const keyed = (now) => !!now.proto;
const RULE_ONLY = {{
  key: "proto",
  map: {{
    port: PORTED, "port-group": PORTED,
    "icmp-type": ["icmp", "icmpv6"],
    // A rule keyed by protocol, which is what `is_port_rule` means: a port on
    // TCP or UDP, or a protocol that carries no ports and is the match itself.
    // The port is beside these, so it is not asked for twice.
    limit: keyed, burst: keyed,
    "schedule days": keyed, "schedule start": keyed, "schedule end": keyed,
  }},
}};

// The editor folds like the add panel does, from the same `FORMS.rule` — one
// rule, one shape, whether it is being made or changed. It used to be the whole
// rule flat, twenty-four boxes under five headings, on the reasoning that an
// editor is opened deliberately and has nothing to reveal; but a rule that sets
// seven of its fields still read as a rule that sets twenty-four, and the fold
// is honest here for the same reason it is in the add panel — a field the rule
// actually carries stays on screen (see `fieldGrid`'s honesty rule), only the
// unset ones go behind "More settings". `openEditor` passes `FORMS.rule`
// directly so the essential set is shared, not copied.

// What the editor is currently editing: the fields it was built from, their
// widgets, and the rule as it was — the last of these is what makes an emptied
// field mean "remove this setting" rather than "leave it alone".
let editing = null;

function script() {{
  const name = $("r-name").value.trim();
  if (!name || !editing) return [];
  return fieldLines(editing.fields, editing.widgets, "firewall rule " + name, editing.before);
}}

// One rule, one shape. The dialog used to unpick the mask and re-lay its fields
// in a grid of its own, so the same rule was a four-column mask when it was
// being created and a single column of twenty rows when it was being edited —
// two forms for one object, and the operator learning both. It holds the mask
// now, exactly as the add panel does, and is wide enough to be one.
function openEditor(rule, zones) {{
  $("editortitle").textContent = rule ? "Edit rule " + rule.name : "New rule";
  $("r-name").value = rule ? rule.name : "";
  $("r-name").readOnly = !!rule;
  const fields = ruleFields(zones || []);
  const {{ grid, widgets, more }} = fieldGrid(fields, rule, null, FORMS.rule);
  const box = $("editorfields");
  // Held before the box is emptied: after the second open the name field is a
  // child of the mask this is about to throw away, and emptying first would
  // detach it and leave `$("r-namefield")` answering null.
  const named = $("r-namefield");
  box.textContent = "";
  maskHost(box);
  // The name leads the mask rather than standing above it, which is where the
  // add panel puts it: two forms for one rule differing only in where its name
  // went is still two forms.
  grid.firstElementChild.prepend(named);
  box.append(grid);
  // The reveal control the fold hands back, placed beside the modal's own
  // buttons and cleared first so re-editing does not stack a second one.
  const moreHost = $("editormore");
  moreHost.textContent = "";
  if (more) moreHost.append(more);
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
  // A read-only account cannot apply, so it must not stage either: a change
  // it builds is a change it can only look at, and one it could not even
  // discard (Discard is gated with Apply). Refused here, once, where the
  // change was attempted — the buttons are gated too, but the lists rebuild
  // themselves after every fetch and a button can be drawn before the gate
  // runs over it, which is how a read-only account came to hold a pending
  // "delete firewall rule".
  if (permission === "read-only") {{
    banner("This account may read the configuration, not change it");
    return;
  }}
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
  $("stagedbadge").className = "pill" + (n ? " warn" : " rest");
  $("stagedbadge").title = n ? "Review the staged changes" : "";
  // Apply and Discard only exist while there is something to apply or discard —
  // a resting header must not offer actions that would do nothing.
  $("discard").classList.toggle("hidden", n === 0);
  $("applystaged").classList.toggle("hidden", n === 0);
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
  // The batch runs once, and the appliance's own report is the answer.
  //
  // Applying used to run every command twice: once with no `commit` to see
  // whether the batch "would be refused", and then again for real. The check
  // could not know anything the real run would not — it ran the same lines
  // against the same configuration — so all it bought was a second execution
  // of the whole batch on every single apply. What it cost was worse: any
  // reply with an `error:` line in it stopped the apply outright, so one
  // refused command meant the changes staged *beside* it were never applied
  // either, and since the refusal names the setting but not which staged
  // change contained it, an operator with several waiting could be left unable
  // to save any of them. The appliance runs a batch line by line, commits what
  // survived and says what it refused; that report is what to show.
  //
  // Checking first is still here — it is what Validate is, and an operator who
  // wants to know before touching the box presses it. What is gone is the
  // hidden second run that every apply paid for and that could refuse a change
  // the appliance was willing to take.
  //
  // Validating runs the same commands with no `commit`, so nothing is applied
  // — and the staged list must survive it. Clearing on a *validate* was the
  // worst possible bug in this panel: the check said "fine", the panel emptied
  // itself, and the change an operator had just been told was good could no
  // longer be applied.
  const committed = tail.includes("commit");
  let r;
  try {{
    r = await configure(stagedCommands().concat(tail));
  }} catch (e) {{
    // An apply that never reached the appliance has to say so. Left to throw,
    // the page swallowed it: no dialog, no banner, the changes still staged —
    // an operator pressing Apply and being answered with nothing at all.
    showResult({{ ok: false, output: "error: " + (e.message || e) }}, committed);
    return;
  }}
  const refused = !r.ok || summarise(r.output).some((n) => n.kind === "bad");
  showResult(r, committed, refused ? await culprit() : null);
  // Only clear once they have actually run. A refused commit leaves the
  // commands staged, so the operator can fix one and try again rather than
  // reconstructing what they had clicked.
  if (committed && !refused) {{
    staged = [];
    renderStaged();
  }}
  await buildSearchIndex();
  await refresh();
}}

// Which staged change the appliance refused.
//
// The reply says what was wrong and never which line said it, and "That
// setting is not one this appliance accepts" is an unanswerable sentence when
// six changes are waiting: the operator cannot tell which one to correct, so
// the batch stays broken and nothing they do afterwards can be applied either.
//
// So the batch is replayed a change at a time — same lines, same order, no
// `commit`, so nothing is applied — and the first prefix that draws a refusal
// names the change that carries it. Only ever after a refusal, and only while
// the list is short enough for that to be quick: this is a hint that costs a
// few seconds in the one case where an operator is stuck, not something every
// apply pays for.
async function culprit() {{
  if (staged.length < 2 || staged.length > 12) return null;
  const sofar = [];
  for (const entry of staged) {{
    sofar.push(...entry.cmds);
    let r;
    try {{
      r = await configure(sofar);
    }} catch (e) {{
      return null;   // a hint is never worth losing the answer over
    }}
    if (!r.ok || summarise(r.output).some((n) => n.kind === "bad")) return entry.label;
  }}
  // The lines that survived were committed and saved, so a replay can come back
  // clean — better to say nothing than to blame the wrong change.
  return null;
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

function showResult(r, committed, blamed) {{
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
  // Which of the waiting changes it came from. First, because a refusal an
  // operator cannot place is one they cannot act on.
  if (blamed) {{
    notes.unshift({{ kind: "bad", text: "The refusal came from: " + blamed +
      " — remove or correct that change, the rest are still staged." }});
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

// `host:port` read back, so the halves can be told apart at a glance. A v6
// endpoint carries colons of its own and is written `[fd00::1]:51820`, which is
// the one case a naive split gets wrong and then says something confident and
// untrue about.
function endpointHint(value) {{
  const text = value.trim();
  if (!text) return "";
  const bracketed = text.match(/^\[(.+)\]:(\d+)$/);
  const plain = bracketed ? null : text.match(/^([^:]+):(\d+)$/);
  const m = bracketed || plain;
  if (!m) {{
    return text.includes(":") && !bracketed
      ? "an IPv6 endpoint is written [address]:port"
      : "needs a port — host:port";
  }}
  const port = Number(m[2]);
  if (port < 1 || port > 65535) return "the port is out of range";
  const named = WELL_KNOWN_PORTS[port] ? ", usually " + WELL_KNOWN_PORTS[port] : "";
  return m[1] + " on port " + port + named;
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

/// What the box's own list has to say, for a setting the appliance validates
/// against a set the console cannot see.
///
/// A bare `<datalist>` shows nothing until somebody types, so an operator who
/// did not already know the answers is looking at a plain box. This says the
/// answers are there and how many, and once there is something in the box it
/// says whether the appliance would take it — at the keyboard rather than at
/// commit, on a box somebody is already logged into.
const choiceHint = (kind, noun) => (value) => {{
  const options = choiceCache[kind];
  if (!options || !options.length) return "";
  const text = value.trim();
  if (!text) {{
    return options.length + " " + noun + "s on this appliance — type to narrow the list";
  }}
  if (options.includes(text)) return "";
  const lower = text.toLowerCase();
  const near = options.filter((o) => o.toLowerCase().includes(lower)).slice(0, 3);
  return near.length ? "did you mean " + near.join(", ") + "?"
                     : "this appliance has no " + noun + " by that name";
}};

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
  port: portHint, "listen-port": portHint, endpoint: endpointHint,
  "geoip-block": countryHint,
  timezone: choiceHint("timezone", "zone"),
  keyboard: choiceHint("keyboard", "keymap"),
  locale: choiceHint("locale", "locale"),
  "validity-days": validityHint, mtu: mtuHint, mru: mtuHint,
}};

// One hint per field, recomputed as it is typed into. Debounced because the
// asynchronous ones cross the network, and a keystroke is not a question.
function wireHint(field, widget, box, values) {{
  const compute = HINTS[field[0]];
  // What the appliance does with an empty box, where that is a sentence rather
  // than a value. It stands under the field, not in it: a placeholder is as
  // wide as its box and a sentence in one is a sentence with its end cut off.
  // Only while the box is empty — once there is a value, what the default was
  // is no longer what happens. Not under a dropdown: its unset entry says the
  // same thing already, and twice is once too often.
  const gloss = widget.tagName === "SELECT" ? "" : defaultGloss(field[0]);
  if (!compute && !gloss) return () => {{}};
  let timer = null;
  const run = () => {{
    const value = widget.value || "";
    const idle = value ? "" : gloss;
    if (!compute) {{ box.textContent = idle; return; }}
    let answer;
    try {{ answer = compute(value, values ? values() : {{}}); }} catch (e) {{ answer = ""; }}
    if (answer && typeof answer.then === "function") {{
      box.textContent = idle;
      answer.then((text) => {{ if (widget.value === value) box.textContent = text || idle; }});
      return;
    }}
    box.textContent = answer || idle;
  }};
  widget.addEventListener("input", () => {{
    clearTimeout(timer);
    timer = setTimeout(run, 300);
  }});
  widget.addEventListener("change", run);
  run();
  // Handed back so a hint whose answer arrives after the render can be redrawn
  // without dispatching an event at the widget: an event would reach the mask's
  // own listener too, and the mask would mark itself changed by somebody.
  return run;
}}

// What already exists, for the fields that point at it.
//
// An operator adding an interface to a bond should be choosing from the
// interfaces this appliance has, not typing a name and finding out at commit
// time that they misremembered it. The vocabulary is read from the same
// configuration every mask is built from.
// The same entries a view would list, plus the ones that exist only as a staged
// change. A name typed into a picker is a thing that exists as far as the
// operator is concerned; a rule editor that will not open until the container
// has been *applied* makes "name a map, then give it a rule" two visits and one
// commit, and says nothing about why the button is dead in between.
function entriesWithStaged(rows, prefix) {{
  const out = rows.slice();
  const have = new Set(out.map((r) => r.name));
  const head = "set " + prefix.join(" ") + " ";
  for (const entry of staged) {{
    for (const command of entry.cmds) {{
      if (!command.startsWith(head)) continue;
      const name = command.slice(head.length).split(/\s+/)[0];
      if (name && !have.has(name)) {{ have.add(name); out.push({{ name }}); }}
    }}
  }}
  return out;
}}

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
  // `acme` is not a certificate somebody named; it is the appliance's own, and
  // the grammar offers it wherever a certificate is asked for.
  certificate: () => [...namesUnder(["pki", "certificate"]), "acme"],
  ca: () => namesUnder(["pki", "ca"]),
  group: () => namesUnder(["system", "group"]),
  "match prefix-list": () => namesUnder(["policy", "prefix-list"]),
  import: () => namesUnder(["policy", "route-map"]),
  export: () => namesUnder(["policy", "route-map"]),
  "prefix-list": () => namesUnder(["policy", "prefix-list"]),
  "source-group": () => namesUnder(["firewall", "group", "address-group"]),
  "destination-group": () => namesUnder(["firewall", "group", "address-group"]),
  "port-group": () => namesUnder(["firewall", "group", "port-group"]),
  "interface-group": () => namesUnder(["firewall", "group", "interface-group"]),
  "source-mac-group": () => namesUnder(["firewall", "group", "mac-group"]),
  "default-group": () => namesUnder(["system", "group"]),
  // Every remaining setting whose value has to be the name of a link this
  // appliance has. A key that carries its path — `bond primary`, `pim
  // interface` — is spelled out, because the first word of those is the block
  // they sit in and says nothing about what may go in the box.
  dev: () => namesUnder(["interface"]),
  "bond primary": () => namesUnder(["interface"]),
  "mirror-ingress": () => namesUnder(["interface"]),
  "mirror-egress": () => namesUnder(["interface"]),
  "pd-from": () => namesUnder(["interface"]),
  "serve-on": () => namesUnder(["interface"]),
  "passive-interface": () => namesUnder(["interface"]),
  "underlay-interface": () => namesUnder(["interface"]),
  "pim interface": () => namesUnder(["interface"]),
  vti: () => namesUnder(["interface"]),
  vrf: () => namesUnder(["protocols", "vrf"]),
  "wan-zone": () => zoneNames(lastLeaves),
  // The uplinks multi-WAN knows, so a policy points at one that exists rather
  // than at an interface name that was never made an uplink.
  uplink: () => namesUnder(["multiwan", "uplink"]),
}};

// Where a setting's name means something else than it does everywhere else.
// `import` is a route map under a BGP neighbour and under `protocols`; under a
// VRF the same word takes a route target — `65001:100` — and offering the box's
// route maps there was a picker whose every answer the appliance refuses.
// Longest matching path wins, and `null` means the field is free text after all.
const PATH_VOCAB = {{
  "protocols vrf": {{ import: null, export: null }},
  // And the other way about: a word too general to answer anywhere becomes an
  // answerable one here. A user group holds the remote-access accounts this
  // box has; `user` elsewhere is a login on somebody else's SMTP relay.
  "firewall group user-group": {{
    user: () => namesUnder(["vpn", "openconnect", "user"]),
  }},
}};
function vocabularyFor(key) {{
  let best = null;
  for (const prefix of Object.keys(PATH_VOCAB)) {{
    if (!fieldPath.startsWith(prefix)) continue;
    if (!(key in PATH_VOCAB[prefix])) continue;
    if (best === null || prefix.length >= best.length) best = prefix;
  }}
  if (best !== null) return PATH_VOCAB[best][key];
  return VOCAB[key] || VOCAB[String(key).split(" ")[0]] || null;
}}

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
    // A tick box may be labelled with something other than what it writes: the
    // days a rule is open are `mon`…`sun` to the appliance and Mon…Sun to
    // anybody reading them.
    const value = optValue(option);
    const tick = el("input", {{ type: "checkbox", value }});
    tick.checked = chosen.has(value);
    tick.onchange = () => box.dispatchEvent(new Event("change"));
    boxes.push(tick);
    box.append(el("label", {{ class: "pickone" }}, [tick, el("span", {{ text: optLabel(option) }})]));
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
  mtu: "1500",
  "pppoe mru": "1492",
  ttl: "0 — inherit from the inner packet",
  "vlan-protocol": "802.1q",
  "validity-days": "3650 for an authority, 825 for a certificate",
  "key-type": "ec",
  "listen-port": "51820",
  "macvlan-mode": "bridge",
  weight: "1",
  mode: "failover",
  // Everything below is read off the appliance's own source rather than
  // remembered from a vendor's documentation: a placeholder that names a
  // default an operator then cannot reproduce is worse than an empty box.
  "hold-time": "180",             // config.rs: proposed in OPEN
  "bond-mode": "active-backup",   // net.rs
  "cache-size": "150",            // dnsmasq's own
  "cgnat-base-port": "32768",     // DEFAULT_CGNAT_BASE_PORT
  "block-duration": "3600",       // DEFAULT_IDS_BLOCK_SECONDS
  "block-severity": "1",          // DEFAULT_IDS_BLOCK_SEVERITY
  "ike-proposal": "aes256-sha256-modp2048",   // DEFAULT_IKE_PROPOSAL
  "esp-proposal": "aes256-sha256-modp2048",   // DEFAULT_ESP_PROPOSAL
  "ike-version": "2",             // ipsec.rs
  "start-action": "start",        // DEFAULT_IPSEC_START_ACTION
  // Named rather than spelled out: the page may not carry an absolute URL, and
  // the directory it stands for is DEFAULT_ACME_DIRECTORY.
  "directory-url": "Let's Encrypt production",
  "ao-key-id": "100",             // config.rs: SendID/RecvID
  "bfd-auth-key-id": "1",
  "min-tx": "300", "min-rx": "300", "detect-mult": "3",
  "echo-interval": "100",
  "check interval": "5", "check timeout": "2",
  "check fail": "3", "check rise": "3",
  "pd-subnet": "0",
  "user-attribute": "uid",        // api.rs
  "ip-type": "ipv4v6",            // wwan.rs
  "wireless band": "g",           // wireless.rs
  "wireless wpa mode": "wpa2",    // wireless.rs
  "dhcp6-pool lease-time": "12h",  // DHCP6_DEFAULT_LEASE
  dnssec: "no",                   // net.rs
  provider: "dyndns2",            // net.rs
  challenge: "http-01",           // acme.rs
  // Not constants, but still what happens when the box is left empty — and
  // that is the question a placeholder answers.
  "cluster-id": "the router id",
  "default-router": "the server's own address",   // net.rs: option 3 unset
  "commit-revisions": "50",                       // archive.rs: ARCHIVE_KEEP
}};

// Defaults that are only true in one place. `priority` means four different
// things in this console — a VRRP election, an IS-IS router priority, an
// uplink's order, a routing rule's slot — and one number in the placeholder
// beside all four was true beside one of them. Longest matching path wins.
const PATH_DEFAULTS = {{
  "protocols vrrp": {{ priority: "100", "advert-interval": "1000" }},
  "protocols ospf": {{
    "hello-interval": "10", "dead-interval": "40",
    "graceful-restart-period": "120", "redistribute-metric": "20",
  }},
  "protocols ospf3": {{ "instance-id": "0", "redistribute-metric": "20" }},
  "protocols bfd": {{ "auth-key-id": "1" }},
  // A burst left alone is one second's worth of the limit, which is what
  // "a hundred a second" already means to the person who typed it.
  "firewall rule": {{ burst: "one second's worth of the limit" }},
  "services reverse-proxy": {{ port: "443" }},
  "services portal": {{ port: "8082", "session-timeout": "3600" }},
  "services syslog": {{ port: "514" }},
  "services ssh": {{ port: "22" }},
  "services flow-export": {{ interval: "30", domain: "1" }},
  "system conntrack-sync": {{ port: "5429", interval: "1" }},
  "system aaa radius": {{ port: "1812", timeout: "3" }},
  "system aaa ldap": {{
    timeout: "5", tls: "ldaps", port: "636 with ldaps, 389 otherwise",
  }},
  "vpn openconnect": {{ port: "443" }},
  "nat nat64": {{ prefix: "64:ff9b::/96 — the well-known NAT64 prefix" }},
  // Which one it is follows from the encapsulation above it, so the field says
  // both rather than naming the one that happens to be commoner.
  evpn: {{ "udp-port": "4789 with VXLAN, 6081 with Geneve" }},
  // The posture, from the Firewall struct's own serde defaults. A zone's is
  // not a constant at all — it is whatever the global posture says — and one
  // table saying "off by default" beside both is the console answering a
  // question it was not asked.
  "firewall global": {{
    "default-action": "drop", stateful: "on", "block-icmp": "off",
    log: "off", "fail-closed": "on", "source-validation": "disable",
  }},
  "firewall zone": {{
    "default-action": "the global posture", stateful: "the global posture",
    "block-icmp": "the global posture", log: "the global posture",
    "source-validation": "the global posture",
  }},
  "pki ca": {{ "validity-days": "3650" }},
  "pki certificate": {{ "validity-days": "825" }},
}};

// The path the mask being built writes into, so a default can be true of one
// place without being claimed everywhere. Set around a render, like
// `fieldSubject`.
let fieldPath = "";

/// What the appliance uses when this field is left alone, or "" where nothing
/// in the source names one. An honest blank, never the label again.
function defaultOf(key) {{
  // Longest match wins, and it has to: `protocols ospf` is a prefix of
  // `protocols ospf3`, so first-match order would hand OSPFv3 the numbers
  // written down for OSPFv2.
  let best = "";
  for (const prefix of Object.keys(PATH_DEFAULTS)) {{
    if (!fieldPath.startsWith(prefix)) continue;
    if (PATH_DEFAULTS[prefix][key] === undefined) continue;
    if (prefix.length >= best.length) best = prefix;
  }}
  if (best) return PATH_DEFAULTS[best][key];
  return DEFAULTS[key] || "";
}}

/// The part of a default that fits in the box, or "" where none of it does.
///
/// A default is sometimes a value and sometimes a sentence about one — a
/// tunnel's TTL is `0`, and what 0 *means* is that the inner packet's TTL is
/// inherited. A placeholder is as wide as its field, so a sentence in one is a
/// sentence with its end cut off: the TTL box read "defaults to 0 -", which
/// says nothing and looks like the appliance stopped mid-word. So the box
/// carries the value and [`defaultGloss`] hands the rest to the hint under it.
function defaultHead(key) {{
  const full = defaultOf(key);
  if (!full) return "";
  const cut = full.indexOf(" — ");
  const head = cut === -1 ? full : full.slice(0, cut);
  // A default with no value in it at all — "the global posture", "the router
  // id" — has no head, and a placeholder guessed out of one is worse than an
  // empty box.
  return head.includes(" ") ? "" : head;
}}

/// The whole of a default, for the hint, where the box could only carry part of
/// it. "" where the placeholder already says all there is to say.
function defaultGloss(key) {{
  const full = defaultOf(key);
  return full.includes(" ") ? defaultLabel(full) : "";
}}

// A shape, not a default: what a value of this kind looks like, for the few
// settings whose format is not guessable from the label. Taken from the
// grammar's own placeholders (`<asn:value>`, `<host:port>`, …) rather than
// invented, and shown as an example so it can never be read as a value.
const EXAMPLES = {{
  community: "65001:100", "large-community": "65001:100:200",
  "ext-community": "rt:65001:100",
  "set community": "65001:100", "set large-community": "65001:100:200",
  "set ext-community": "rt:65001:100",
  "set add-community": "65001:100", "set add-large-community": "65001:100:200",
  "set add-ext-community": "rt:65001:100",
  rd: "65001:100", "rt-import": "65001:100", "rt-export": "65001:100",
  // A VRF's import and export are route targets, not route maps — see
  // PATH_VOCAB, which is what stops the box offering the wrong thing.
  import: "65001:100", export: "65001:100",
  "system-id": "0100.1001.0001", area: "49.0001",
  "nssa-area": "0.0.0.1", "stub-area": "0.0.0.1",
  "totally-stubby-area": "0.0.0.1", "totally-nssa-area": "0.0.0.1",
  "nssa-default-area": "0.0.0.1",
  collector: "10.0.0.9:2055", "rpki rtr": "10.0.0.9:3323",
  endpoint: "203.0.113.9:51820", backends: "10.0.0.5:8080",
  "schedule start": "08:00", "schedule end": "18:00",
  "schedule days": "mon,tue,wed,thu,fri",
  "host-override": "printer.example.com 10.0.0.9",
  "txt-record": "_acme-challenge.example.com token",
  "subject-alt-name": "DNS:vpn.example.com",
  "geoip-block": "CN,RU", block: "198.51.100.0/24",
  "dhcp duid": "00:03:00:01:02:00:00:00:00:01",
  "dhcpv6 duid": "00:03:00:01:02:00:00:00:00:01",
  // The tzdb has four hundred names in it. A dropdown of four hundred is not a
  // control anybody can use — that wants a search box, which is more than this
  // pass — so it stays a field, with the shape of an answer in it.
  timezone: "Europe/Berlin",
  locale: "en_US.UTF-8", keyboard: "de", "console device": "ttyS0",
  // tc's own spelling, which the appliance validates as written. `interval`
  // only reaches this where no default claims it, which is the shaping mask.
  bandwidth: "100mbit", interval: "5ms", target: "5ms",
  "macsec-peer": "02:00:00:00:00:01", "hw-id": "02:00:00:00:00:01",
  "wireless country": "DE",
}};

// The same word, a different shape, depending on where it is being set. An
// OSPF area is `0.0.0.0` or a number; an IS-IS area is an NET address prefix
// like `49.0001`, and one example beside both was wrong beside one of them.
// Longest matching path wins, as with the defaults.
const PATH_EXAMPLES = {{
  "protocols ospf": {{ area: "0.0.0.0" }},
  "protocols ospf3": {{ area: "0.0.0.0" }},
  "protocols isis": {{ area: "49.0001" }},
}};
function exampleOf(key) {{
  let best = "";
  for (const prefix of Object.keys(PATH_EXAMPLES)) {{
    if (!fieldPath.startsWith(prefix)) continue;
    if (PATH_EXAMPLES[prefix][key] === undefined) continue;
    if (prefix.length >= best.length) best = prefix;
  }}
  if (best) return PATH_EXAMPLES[best][key];
  return EXAMPLES[key] || "";
}}

// The whole numbers. A bounded integer is not free-form text: the appliance
// already knows what may go in it, so the box knows too — the range comes from
// the CLI grammar's own placeholder (`<1-65535>`, `<1-4094>`, `<68-9216>`, …),
// and where the grammar declares only "a number" no upper bound is invented.
// `unit` is what the figure is counted in, shown beside the box instead of
// inside the label: a unit belongs to the value, not to its name.
const NUM = {{
  // ports
  port: [1, 65535], "listen-port": [1, 65535], "source-port": [1, 65535],
  "destination-port": [1, 65535], "udp-port": [1, 65535],
  "cgnat-base-port": [1, 65535], "cgnat-block-size": [1, 65535],
  // AS numbers
  "local-as": [1, 4294967295], "remote-as": [1, 4294967295],
  "origin-as": [1, 4294967295], "confederation id": [1, 4294967295],
  // link sizes
  mtu: [68, 9216, "bytes"], "pppoe mru": [68, 9216, "bytes"],
  vlan: [1, 4094], "vlan-untagged": [1, 4094],
  ttl: [0, 255], "ebgp-multihop": [0, 255, "hops"], "ttl-security": [0, 255, "hops"],
  key: [0, 4294967295],
  ge: [0, 128], le: [0, 128], "match metric-ge": [0, 128],
  "match metric-le": [0, 128], "prefix-length": [0, 128],
  "pd-subnet": [0, 255],
  // times
  "hold-time": [0, 65535, "s"], "hello-interval": [1, null, "s"],
  "dead-interval": [1, null, "s"], "graceful-restart-period": [1, null, "s"],
  "pim hello-interval": [1, null, "s"], "query-interval": [1, null, "s"],
  "query-response-interval": [1, null, "s"], "max-lifetime": [0, null, "s"],
  "router-lifetime": [0, null, "s"], "negative-ttl": [0, null, "s"],
  "session-timeout": [0, null, "s"], "block-duration": [0, null, "s"],
  "rpki rtr-refresh": [1, null, "s"], "ip arp-cache-timeout": [1, null, "s"],
  "bridge ageing-time": [0, null, "s"], "bridge forward-delay": [0, null, "s"],
  "bridge hello-time": [1, null, "s"], "bridge max-age": [1, null, "s"],
  "check interval": [1, null, "s"], "check timeout": [1, null, "s"],
  "validity-days": [1, null, "days"],
  "min-tx": [1, null, "ms"], "min-rx": [1, null, "ms"],
  "echo-interval": [1, null, "ms"], "advert-interval": [1, null, "ms"],
  "bond mii-interval": [0, null, "ms"], "bond arp-interval": [0, null, "ms"],
  "check jitter": [0, null, "ms"], "check latency": [0, null, "ms"],
  "ethernet rx-usecs": [0, null, "µs"], "ethernet tx-usecs": [0, null, "µs"],
  // counts and weights
  cost: [0, 65535], metric: [0, null], "redistribute-metric": [0, null],
  "set metric": [0, null], "set add-metric": [0, null],
  "set preference": [0, null], distance: [1, 255],
  priority: [0, null], "router-priority": [0, 255],
  "bridge priority": [0, 65535], "bridge-port priority": [0, 63],
  "bridge-port cost": [1, null], weight: [1, null],
  "priority-decrement": [1, 254], vrid: [1, 255],
  "detect-mult": [1, 255], "auth-key-id": [0, 255],
  "ao-key-id": [0, 255], "bfd-auth-key-id": [0, 255],
  "check fail": [1, null], "check rise": [1, null], "check probes": [1, null],
  "check loss": [0, 100, "%"], multipath: [1, null, "paths"],
  "max-prefix": [1, null, "prefixes"], "max-length": [0, 128],
  "stub-default-cost": [0, null], table: [0, 4294967295],
  "commit-revisions": [1, null], "cache-size": [0, null],
  "pool-size": [1, null], "pool-offset": [0, null],
  "bond min-links": [0, null], robustness: [1, 255],
  "ipv6 dad-transmits": [0, null], "instance-id": [0, 255],
  evi: [1, null], vni: [1, 16777215], "l3-vni": [1, 16777215],
  "dhcp default-route-distance": [1, 255],
  "ethernet rx-ring": [1, null], "ethernet tx-ring": [1, null],
  "ethernet speed": [10, null, "Mbit/s"], "console speed": [1200, null, "baud"],
  "wireless channel": [0, 196], "wireless max-stations": [1, null],
  "pim spt-threshold": [0, null, "kbit/s"],
  mss: [1, null, "bytes"], "block-severity": [1, 4],
  timeout: [1, null, "s"], limit: [1, null], burst: [1, null],
  // `interval` is milliseconds in one mask and seconds in two others, so it
  // gets the box and the range but no unit: a unit guessed is a unit wrong.
  interval: [1, null],
  keepalive: [1, null, "s"],
}};

// Where a setting that is a figure almost everywhere may be something else.
// A firewall rule's port is `443` or `8000-8100`, and a box that only takes
// digits makes the second one unsayable — which is the opposite of the point.
// Traffic shaping speaks tc's own language — `100mbit`, `5ms` — and those are
// not figures either, however much they look like one with a unit stuck on.
const RANGED = {{
  "firewall rule": ["port"],
  interface: ["interval"],
}};
function ranged(key) {{
  for (const prefix of Object.keys(RANGED)) {{
    if (fieldPath.startsWith(prefix) && RANGED[prefix].includes(key)) return true;
  }}
  return false;
}}

// And the other way round: a word that is text almost everywhere and a bounded
// figure in one place. `domain` is a DNS domain on a DHCP server and a 32-bit
// observation domain in the flow exporter, so the range belongs to the path.
const PATH_NUM = {{
  "services flow-export": {{ domain: [0, 4294967295] }},
  // A rule's rate limit is packets a second and its burst is packets; the same
  // two words under `interface … qos` are an fq_codel backlog, which is a
  // depth and not a rate. One unit beside both would be wrong beside one.
  "firewall rule": {{ limit: [1, null, "packets/s"], burst: [1, null, "packets"] }},
  // Ports per host and the port they start at: figures with a range the
  // appliance already bounds, and a unit that says which of the two is which.
  "nat source": {{ "cgnat-block-size": [1, 65535, "ports"] }},
}};
function boundsOf(key) {{
  for (const prefix of Object.keys(PATH_NUM)) {{
    if (fieldPath.startsWith(prefix) && PATH_NUM[prefix][key]) return PATH_NUM[prefix][key];
  }}
  return NUM[key] || null;
}}

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
  "seq", "table", "vrf", "asn", "local-as", "remote-as", "area",
  "vrid", "block-size", "cgnat-block-size", "timeout",
];
const WIDTH = {{}};
for (const k of NARROW) WIDTH[k] = "w-s";
// A figure with a known range needs room for the figure and no more.
for (const k of Object.keys(NUM)) WIDTH[k] = "w-s";
// And a value with two halves in it needs the run: a name and an address, a
// record and its content. In a column sized for a port they are typed into a
// box that shows a third of what is in it.
for (const k of ["host-override", "txt-record"]) WIDTH[k] = "w-l";

const SUGGEST = {{
  mac: () => {{
    // Locally administered, unicast: the range set aside for exactly this.
    const bytes = [0x02];
    for (let i = 0; i < 5; i++) bytes.push(Math.floor(Math.random() * 256));
    return bytes.map((b) => b.toString(16).padStart(2, "0")).join(":");
  }},
  "private-key": () => "generate",
  // The appliance mints this one too, and prints it — a pre-shared key has to
  // be carried to the far end, so it is deliberately not a secret this box
  // keeps to itself.
  "preshared-key": () => "generate",
  // A base32 secret the browser makes, so it is never carried anywhere it does
  // not have to be. The appliance validates it on commit either way.
  totp: () => {{
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const raw = new Uint8Array(20);
    crypto.getRandomValues(raw);
    return [...raw].map((b) => alphabet[b & 31]).join("");
  }},
}};

// Settings whose answer is usually one of a handful the appliance already knows
// — but not necessarily. A router id is normally one of this box's addresses and
// is legally any 32-bit value; a tunnel is normally sourced from an address
// configured here and may be sourced from one that is not yet. A picker would
// make the unusual answer unsayable, so these are offered rather than imposed:
// the box's own answers drop down, and anything else can still be typed.
// Named so one list can serve every field that offers the same thing: a
// `<datalist>` is addressed by id, and a fresh one per box would be sixty
// copies of the same six addresses.
/// The network an interface address sits in, which is what a firewall rule or a
/// BGP `network` statement is written with — an operator holds `10.0.0.1/24` in
/// their head and has to hand-carry it to `10.0.0.0/24` every time.
function networkOf(cidr) {{
  const [addr, bitsText] = String(cidr).split("/");
  const bits = Number(bitsText);
  if (!addr || !Number.isInteger(bits)) return "";
  if (addr.includes(":")) return v6Network(addr, bits);
  const octets = addr.split(".").map(Number);
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o > 255)) return "";
  if (bits < 0 || bits > 32) return "";
  const base = ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
  const first = bits === 0 ? 0 : (base & ~((Math.pow(2, 32 - bits)) - 1)) >>> 0;
  return [24, 16, 8, 0].map((sh) => (first >>> sh) & 255).join(".") + "/" + bits;
}}

/// The same, for IPv6. Written out byte by byte rather than with a shortcut for
/// prefixes that fall on a group boundary: /56 does not, and a rule offering a
/// prefix that is nearly the right one is worse than offering none.
function v6Network(addr, bits) {{
  if (bits < 0 || bits > 128) return "";
  const [head, tail] = addr.split("::");
  const part = (s) => (s ? s.split(":").filter(Boolean) : []);
  const left = part(head), right = tail === undefined ? [] : part(tail);
  if (tail === undefined && left.length !== 8) return "";
  const groups = tail === undefined
    ? left
    : [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-fA-F]{{1,4}}$/.test(g))) return "";
  const bytes = [];
  for (const g of groups) {{
    const n = parseInt(g, 16);
    bytes.push((n >> 8) & 255, n & 255);
  }}
  for (let i = 0; i < 16; i++) {{
    const keep = Math.min(8, Math.max(0, bits - i * 8));
    bytes[i] &= keep === 8 ? 255 : (0xff << (8 - keep)) & 255;
  }}
  const out = [];
  for (let i = 0; i < 16; i += 2) out.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  // Compressed the way anybody would write it: the longest run of zero groups
  // becomes `::`, since an uncompressed prefix in a picker is a prefix nobody
  // recognises as the one they configured.
  let bestAt = -1, bestRun = 0, at = -1, run = 0;
  out.forEach((g, i) => {{
    if (g === "0") {{ if (at === -1) at = i; run++; if (run > bestRun) {{ bestRun = run; bestAt = at; }} }}
    else {{ at = -1; run = 0; }}
  }});
  const text = bestRun > 1
    ? out.slice(0, bestAt).join(":") + "::" + out.slice(bestAt + bestRun).join(":")
    : out.join(":");
  return text + "/" + bits;
}}

/// Every prefix this appliance is configured to sit in, which is what a rule
/// about "the office network" or "the guest network" is actually written with.
function configuredSubnets() {{
  const out = [];
  for (const l of lastLeaves) {{
    if (l.path[0] !== "interface") continue;
    const leaf = l.path[l.path.length - 1];
    if (leaf !== "address" && leaf !== "address6") continue;
    for (const one of String(l.value).split(/[,\s]+/)) {{
      if (!one.includes("/")) continue;
      const net = networkOf(one.trim());
      if (net && !out.includes(net)) out.push(net);
    }}
  }}
  return out;
}}

/// The subnets, with `any` in front of them. A rule that matches everything is
/// the commonest rule there is, and `any` is the word the appliance takes for
/// it — leaving it to be remembered is how a rule ends up with a blank that
/// means the same thing and reads as an unfinished form.
const anySubnet = () => ["any", ...configuredSubnets()];

/// The addresses this appliance has promised to particular machines.
///
/// A port forward points at a host, and the hosts this box can honestly name
/// are its DHCP *reservations* — not its leases. A lease is by definition an
/// address that will be something else next week, and a port forward aimed at
/// one is a port forward that breaks quietly; the console offering it would be
/// recommending the mistake.
function reservedHosts() {{
  const byName = new Map();
  for (const l of lastLeaves) {{
    if (l.path[0] !== "interface" || l.path[2] !== "dhcp-server") continue;
    if (l.path[3] !== "static-mapping" || l.path[5] !== "ip") continue;
    byName.set(String(l.value), l.path[4]);
  }}
  return [...byName].map(([ip, name]) => ({{ value: ip, label: ip + " · " + name }}));
}}

/// The ports that have a name, as the name and the number together. Sorted by
/// number, because that is the order somebody scanning for "the low one" reads.
function wellKnownPorts() {{
  return Object.keys(WELL_KNOWN_PORTS)
    .map(Number)
    .sort((a, b) => a - b)
    .map((n) => ({{ value: String(n), label: n + " · " + WELL_KNOWN_PORTS[n] }}));
}}

// The communities this appliance takes by name. RFC 1997's three and no more:
// `blackhole` and `graceful-shutdown` are real communities with real meanings
// and this box does not know either word, so a chip offering one would be the
// console recommending a value its own validator refuses. Kept honest by
// `every_community_offered_is_one_the_appliance_takes`.
const WELL_KNOWN_COMMUNITIES = ["no-export", "no-advertise", "no-export-subconfed"];

const OFFERS = {{ address: localAddresses }};
const OFFERED = {{
  "router-id": "address",
  // Unset, it is the router id — which is itself usually one of these.
  "cluster-id": "address",
  "vtep-ip": "address",
  "srv6-source": "address",
  // The address a tunnel leaves by, and the one a service listens on.
  local: "address",
  listen: "address",
  "listen-address": "address",
}};

// The same idea, where what may be offered depends on which mask the field is
// in. A firewall rule's `port` may be `8000-8100`, so it is the one place the
// setting is text rather than a bounded figure — and the one place an operator
// is naming a *service* rather than counting. `to` is a zone on a rule and the
// machine a forward points at under `nat destination`, and a table keyed by
// name alone would offer this box's DHCP reservations in both. Longest prefix
// wins, as everywhere else that a path decides what a word means.
const PATH_OFFERS = {{
  "firewall rule": {{
    port: wellKnownPorts,
    source: anySubnet, destination: anySubnet,
  }},
  "nat destination": {{ to: reservedHosts }},
}};
function offersFor(key) {{
  let best = null;
  for (const prefix of Object.keys(PATH_OFFERS)) {{
    if (!fieldPath.startsWith(prefix)) continue;
    if (!(key in PATH_OFFERS[prefix])) continue;
    if (best === null || prefix.length >= best.length) best = prefix;
  }}
  if (best === null) return null;
  const make = PATH_OFFERS[best][key];
  return make ? make() : null;
}}

// Lists whose usual answers are worth having beside the box, added to what is
// there rather than replacing it. See [`chipsWidget`] for why these are not
// tick boxes: every one of them is legally open, and a picker would make the
// unusual answer unsayable.
const CHIPPED = {{
  // No chips for the large and extended communities: neither has values with
  // a meaning anybody agreed on — they are `<asn>:<n>:<n>` and `rt:<asn>:<n>`,
  // local conventions all the way down — and a chip offering one would be this
  // console recommending a number it made up.
  "protocols bgp": {{ network: configuredSubnets, community: () => WELL_KNOWN_COMMUNITIES }},
  "policy route-map": {{
    "set community": () => WELL_KNOWN_COMMUNITIES,
    "set add-community": () => WELL_KNOWN_COMMUNITIES,
  }},
  // Who may ask this box a question. The appliance takes prefixes here, not
  // zone names — so what is offered is the prefixes the zones actually sit in,
  // which is what "let the office network use the resolver" means when it is
  // written down. Anything else is still typed, since the answer is legally any
  // prefix and is sometimes one this box is not itself on.
  "services dns": {{ "allow-from": configuredSubnets }},
  "services ntp": {{ "allow-from": configuredSubnets }},
  "services snmp": {{ allow: configuredSubnets }},
}};
function chipsFor(key) {{
  let best = null;
  for (const prefix of Object.keys(CHIPPED)) {{
    if (!fieldPath.startsWith(prefix)) continue;
    if (!(key in CHIPPED[prefix])) continue;
    if (best === null || prefix.length >= best.length) best = prefix;
  }}
  if (best === null) return null;
  const options = CHIPPED[best][key]();
  return options.length ? options : null;
}}

// Settings that are a time of day. The appliance takes `HH:MM` and nothing
// else, which is exactly what this control produces — and it produces it in
// whatever way the operator's own platform does clocks, rather than making
// them guess whether this box wants `9:00`, `09:00` or `9am`.
const TIMES = ["schedule start", "schedule end"];

// Settings whose answers are a closed set the appliance knows and this page
// deliberately does not: the zones tzdata installed, the keymaps the console
// package carries, the locales glibc built. Four hundred timezones in a
// `<select>` is a control nobody can use and a page that takes measurably
// longer to build, and four hundred in a table compiled into this console is a
// list that goes stale against the box's own validator. So the box is asked,
// and the answers land in a `<datalist>`: type to narrow it, or open it and
// pick, and anything else the appliance would take can still be typed.
const CHOICES = {{ timezone: "timezone", keyboard: "keyboard", locale: "locale" }};
// Asked once per session. The answer is a property of the image, so re-asking
// on every render would be a request per keystroke's worth of re-layout.
const choiceCache = {{}};
// What to redraw when a list finally lands. The fetch outlives the render that
// started it, so the field that asked has already been built and said what it
// could — which, before the answers arrive, is nothing.
const choiceWaiters = {{}};
function onChoices(kind, fn) {{
  if (choiceCache[kind]) {{ fn(); return; }}
  (choiceWaiters[kind] = choiceWaiters[kind] || []).push(fn);
}}

/// The id of the shared `<datalist>` for a closed set, filled from the
/// appliance the first time something asks for it.
///
/// The id is returned straight away and the options arrive when they arrive: a
/// `<datalist>` is addressed by id, so a list that fills a moment later fills
/// every box already pointing at it. A box whose answers never arrive — an
/// appliance with no zoneinfo, a walk that never let the fetch finish — is the
/// plain box it has always been, which is the correct thing to degrade to.
function choiceList(kind) {{
  const id = "choices-" + kind;
  let list = $(id);
  if (!list) {{
    list = el("datalist", {{ id }});
    document.body.append(list);
  }}
  if (choiceCache[kind]) {{
    if (list.children.length !== choiceCache[kind].length) {{
      list.textContent = "";
      for (const one of choiceCache[kind]) list.append(el("option", {{ value: one }}));
    }}
    return id;
  }}
  if (choiceCache[kind] === undefined) {{
    // Marked as asked before the request goes out, or a mask with three of
    // these fields in it asks three times.
    choiceCache[kind] = null;
    api("/api/v1/choices/" + encodeURIComponent(kind))
      .then((r) => r.json())
      .then((body) => {{
        choiceCache[kind] = body.options || [];
        const now = $(id);
        if (now) {{
          now.textContent = "";
          for (const one of choiceCache[kind]) now.append(el("option", {{ value: one }}));
        }}
        for (const fn of choiceWaiters[kind] || []) {{ try {{ fn(); }} catch (e) {{}} }}
        choiceWaiters[kind] = [];
      }})
      // Silently: this is an offer, and a red banner because a picker could not
      // be filled would be the console complaining about its own convenience.
      .catch(() => {{ choiceCache[kind] = []; }});
  }}
  return id;
}}

/// The id of the shared suggestion list for `name`, refreshed from the
/// configuration as it stands now, or "" where there is nothing to suggest.
function offerList(name) {{
  const options = (OFFERS[name] || (() => []))();
  const id = "offer-" + name;
  let list = $(id);
  if (!options.length) {{
    if (list) list.remove();
    return "";
  }}
  if (!list) {{
    list = el("datalist", {{ id }});
    document.body.append(list);
  }}
  list.textContent = "";
  for (const one of options) list.append(el("option", {{ value: one }}));
  return id;
}}

// The object a form is about, so its own name can be kept out of the choices
// it offers. Set around a render rather than threaded through every call.
let fieldSubject = "";

/// A setting with two states and a third condition: not set at all.
///
/// A dropdown of "", "true", "false" made every one of these read as a
/// question with three answers, when the question is "is this on?" and the
/// third state is "you have not said". So the state is a switch, and not
/// having said is its own resting appearance — greyed, knob left, and the word
/// beside it says so rather than claiming "off". Operating it commits to on or
/// off; `use default` puts it back to unsaid, which is the only way an
/// operator can hand the decision back to the appliance.
///
/// The `<select>` inside carries the value. It is the same three options the
/// field always had, so everything that reads a widget — staging, the tests
/// that fill a mask — goes on seeing one control with a `.value`, and the
/// switch is what a person operates.
function switchWidget(key, value, name) {{
  const box = el("span", {{ class: "switch" }});
  const carrier = el("select", {{ class: "carrier" }});
  for (const option of ["", "true", "false"]) {{
    const o = el("option", {{ value: option }});
    if (option === (value || "")) o.setAttribute("selected", "selected");
    carrier.append(o);
  }}
  // A `<label>` cannot name a button, so the switch carries its own name.
  const knob = el("button", {{
    class: "knob", type: "button", role: "switch", "aria-label": name || key,
  }});
  const state = el("span", {{ class: "switchstate" }});
  const clear = el("button", {{ class: "suggest", type: "button", text: "use default" }});
  // What the appliance does with this one left alone: a word for a constant,
  // a phrase where the answer is another setting.
  const known = defaultOf(key);
  const unset = !known ? "not set"
    : known === "on" || known === "off" ? "not set — " + known + " by default"
    : "not set — " + known;
  const paint = () => {{
    const v = carrier.value;
    knob.setAttribute("data-state", v || "unset");
    knob.setAttribute("aria-checked", v === "true" ? "true" : "false");
    state.textContent = v === "true" ? "on" : v === "false" ? "off" : unset;
    clear.classList.toggle("hidden", !v);
  }};
  const put = (v) => {{
    carrier.value = v;
    paint();
    box.dispatchEvent(new Event("change"));
  }};
  // On pointer-down, not on the click: the press is when the decision is made,
  // and a control that waits for the release to move feels like it is thinking.
  knob.onpointerdown = (e) => {{
    // Prevented so the press does not select the text beside it — and focus
    // moved by hand, because preventing the press is also what would have
    // stopped the button being focused at all.
    e.preventDefault();
    knob.focus();
    put(carrier.value === "true" ? "false" : "true");
  }};
  knob.onclick = (e) => e.preventDefault();
  knob.onkeydown = (e) => {{
    if (e.key !== " " && e.key !== "Enter") return;
    e.preventDefault();
    put(carrier.value === "true" ? "false" : "true");
  }};
  clear.onclick = (e) => {{ e.preventDefault(); put(""); }};
  // Anything that sets the carrier directly — a test filling a mask, the
  // coverage walk — still moves the switch.
  carrier.addEventListener("change", paint);
  Object.defineProperty(box, "value", {{
    get: () => carrier.value,
    set: (v) => {{ carrier.value = String(v || ""); paint(); }},
  }});
  box.append(carrier, knob, state, clear);
  paint();
  return box;
}}

/// A whole number the appliance bounds, with its unit beside it.
///
/// The bounds are the grammar's, so the box refuses what the CLI would refuse —
/// at the keyboard rather than at commit — and the arrow keys and the spinner
/// step through the range. The unit sits next to the figure instead of inside
/// the label, because it belongs to the value.
function numberWidget(key, value, bounds) {{
  const [min, max, unit] = bounds;
  // A bare grey figure is how a default reads in a box that only takes figures.
  // Only the figure: a box this narrow holds a number and not the sentence
  // around one, and the sentence is under the field where it fits.
  const input = el("input", {{
    type: "number", inputmode: "numeric", value: value || "",
    placeholder: defaultHead(key),
  }});
  if (min !== null && min !== undefined) input.setAttribute("min", String(min));
  if (max !== null && max !== undefined) input.setAttribute("max", String(max));
  if (!unit) return input;
  const box = el("span", {{ class: "num" }}, [input, el("span", {{ class: "unit", text: unit }})]);
  Object.defineProperty(box, "value", {{
    get: () => input.value,
    set: (v) => {{ input.value = v; }},
  }});
  for (const kind of ["input", "change"]) {{
    input.addEventListener(kind, () => box.dispatchEvent(new Event(kind)));
  }}
  return box;
}}

/// A box you type into, with the answers this appliance already has beside it.
///
/// A router id must be one of this box's own addresses in every configuration
/// anybody actually runs, and is legally any 32-bit value — so a picker would
/// make the unusual answer unsayable and a bare box makes the usual one a
/// memory test. The `<datalist>` was meant to be the middle ground and is not
/// one: it shows nothing until somebody types, so the offer only ever reached
/// an operator who already knew what to type. The list is given a control.
/// An option is either a bare value or a value with a name for it: a port
/// picker that lists `443` says less than one that lists `443 · https`, and
/// what goes in the box is still `443`.
const optValue = (o) => (o && typeof o === "object" ? o.value : o);
const optLabel = (o) => (o && typeof o === "object" ? o.label : o);

function comboWidget(input, options) {{
  const box = el("span", {{ class: "combo" }}, [input]);
  const menu = el("div", {{ class: "menu hidden" }});
  const close = () => menu.classList.add("hidden");
  for (const option of options) {{
    const one = optValue(option);
    menu.append(el("button", {{
      class: "choice", type: "button", text: optLabel(option),
      onclick: (e) => {{
        e.preventDefault();
        input.value = one;
        close();
        // Through the input, so everything listening to the field — the hint,
        // the mask that folds by what is chosen, the not-staged-yet mark —
        // hears a value arriving the same way it hears one typed.
        for (const kind of ["input", "change"]) input.dispatchEvent(new Event(kind));
      }},
    }}));
  }}
  box.append(el("button", {{
    class: "caret", type: "button", text: "▾",
    title: "What this appliance already holds",
    onclick: (e) => {{ e.preventDefault(); menu.classList.toggle("hidden"); }},
  }}), menu);
  // Leaving the field closes it: a menu left open over the next row is a menu
  // about a field nobody is looking at any more.
  box.addEventListener("focusout", (e) => {{
    if (!box.contains(e.relatedTarget)) close();
  }});
  Object.defineProperty(box, "value", {{
    get: () => input.value,
    set: (v) => {{ input.value = String(v === null || v === undefined ? "" : v); }},
  }});
  for (const kind of ["input", "change"]) {{
    input.addEventListener(kind, () => box.dispatchEvent(new Event(kind)));
  }}
  return box;
}}

/// A list you type into, with the usual answers as chips beside it.
///
/// The middle ground a picker cannot reach and a bare box will not offer. A
/// BGP community is legally any 32-bit pair and is `no-export` nine times out
/// of ten; the networks a router originates are usually the ones configured on
/// it and occasionally are not. Tick boxes would make the tenth case unsayable
/// and a bare box makes the nine a memory test, so the offers *add themselves*
/// to whatever is in the box rather than replacing it — which is the one
/// behaviour a `combo` cannot have, because a list is not one value.
function chipsWidget(input, options) {{
  const box = el("span", {{ class: "chips" }}, [input]);
  const row = el("span", {{ class: "chiprow" }});
  const parts = () => input.value.split(",").map((s) => s.trim()).filter(Boolean);
  const chips = [];
  for (const option of options) {{
    const one = optValue(option);
    const chip = el("button", {{
      class: "chip", type: "button", text: optLabel(option),
      // Not "add": a chip an operator ticked on by mistake has to come off
      // again, and the only other way is to find it in a comma-separated line.
      onclick: (e) => {{
        e.preventDefault();
        const have = parts();
        const at = have.indexOf(one);
        if (at === -1) have.push(one); else have.splice(at, 1);
        input.value = have.join(",");
        for (const kind of ["input", "change"]) input.dispatchEvent(new Event(kind));
      }},
    }});
    chips.push([chip, one]);
    row.append(chip);
  }}
  const paint = () => {{
    const have = new Set(parts());
    for (const [chip, one] of chips) chip.classList.toggle("on", have.has(one));
  }};
  input.addEventListener("input", paint);
  input.addEventListener("change", paint);
  box.append(row);
  Object.defineProperty(box, "value", {{
    get: () => input.value,
    set: (v) => {{ input.value = String(v === null || v === undefined ? "" : v); paint(); }},
  }});
  for (const kind of ["input", "change"]) {{
    input.addEventListener(kind, () => box.dispatchEvent(new Event(kind)));
  }}
  paint();
  return box;
}}

function fieldWidget(field, value) {{
  // A heading, not a setting: eighteen inputs in one flat grid is a form nobody
  // reads top to bottom, and the groups are how an operator already thinks
  // about the protocol — where it speaks, how fast, who it trusts.
  if (field[0] === "#") return null;
  // A field that points at something the appliance already has is a choice,
  // not a spelling test. A key that carries its path — `import bgp`, `export
  // ospf` — is answered by the first word: what may go there is decided by the
  // setting, not by which protocol it is about. Except where the path says
  // otherwise, which is what `vocabularyFor` is looking up.
  const vocab = vocabularyFor(field[0]);
  let vocabulary = vocab ? vocab() : null;
  // Nothing may point at itself: a bond offered as its own member is a choice
  // whose only outcome is the appliance saying no.
  if (vocabulary && fieldSubject) {{
    vocabulary = vocabulary.filter((option) => option !== fieldSubject);
  }}
  if (vocabulary) {{
    // Whatever is set is offered, even where the vocabulary does not know it:
    // a picker that quietly drops a value it cannot account for turns "I edited
    // the description" into "I deleted the time zone", and the operator finds
    // out from the diff.
    if (value && !vocabulary.includes(value)) vocabulary = [value, ...vocabulary];
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
  // Two states and "not said" is not a dropdown of three words.
  if (isBool(field[2])) return switchWidget(field[0], value, field[1]);
  if (!field[2]) {{
    // A time of day is not free text and not a figure: the platform already has
    // a control for one, and it is the only one that cannot be typed wrong.
    //
    // With one caution. The appliance's own parser takes `9:00` as readily as
    // `09:00`, and a `type=time` input refuses anything unpadded — it would
    // have shown an empty box for a window somebody had configured, and then
    // staged a delete of it. So the value is padded on the way in, and a value
    // that is not a time at all keeps the plain box it came from rather than
    // disappearing into a control that will not hold it.
    if (TIMES.includes(field[0])) {{
      const hhmm = String(value || "").match(/^(\d{{1,2}}):(\d{{1,2}})$/);
      if (!value || hhmm) {{
        const padded = hhmm
          ? hhmm[1].padStart(2, "0") + ":" + hhmm[2].padStart(2, "0") : "";
        return el("input", {{ type: "time", value: padded }});
      }}
    }}
    // A repeatable setting is a list typed as one line, so it is not a figure
    // even where each item is one.
    const bounds = boundsOf(field[0]);
    if (!field[3] && bounds && !ranged(field[0])) {{
      return numberWidget(field[0], value, bounds);
    }}
    // The placeholder carries the appliance's own default, or an example of the
    // shape where the format is not obvious, or nothing. Never the label again:
    // "hold time" under a box labelled "Hold time" is a word doing no work.
    // The value of the default, not the sentence about it: what a box this wide
    // cannot hold goes under the field, where it can be read to the end.
    const fallback = defaultHead(field[0]);
    const shape = exampleOf(field[0]);
    const box = el("input", {{
      value: value || "",
      placeholder: fallback ? defaultLabel(fallback) : shape ? "e.g. " + shape : "",
    }});
    // A closed set too long to be a dropdown: the box keeps the keyboard and
    // the appliance's own answers drop out of it.
    if (CHOICES[field[0]]) {{
      box.setAttribute("list", choiceList(CHOICES[field[0]]));
      return box;
    }}
    // A list with usual answers gets them as chips, which add rather than
    // replace — see [`chipsWidget`].
    const chips = field[3] ? chipsFor(field[0]) : null;
    if (chips) return chipsWidget(box, chips);
    // What the appliance would answer with, offered from the box itself. Not a
    // `<select>`: these are suggestions, and the field still takes anything the
    // CLI takes — a router id is usually one of this box's addresses and is
    // legally any 32-bit value.
    const scoped = field[3] ? null : offersFor(field[0]);
    const offers = scoped || (OFFERED[field[0]]
      ? (OFFERS[OFFERED[field[0]]] || (() => []))() : []);
    if (!offers.length) return box;
    // The shared `<datalist>` only exists for the offers that are named in
    // `OFFERS`; a path-scoped one is the menu on the control and nothing else,
    // since a list keyed by field name alone would be the wrong list on the
    // next mask that has a `port` in it.
    if (!scoped) {{
      const offered = offerList(OFFERED[field[0]]);
      if (offered) box.setAttribute("list", offered);
    }}
    return comboWidget(box, offers);
  }}
  const sel = el("select", {{}});
  const fallback = defaultOf(field[0]);
  // Whatever is set is offered, even where the list does not have it: a
  // WireGuard link's `type` is set by the VPN section and is deliberately not
  // in this list, and a dropdown that quietly falls back to its first entry
  // would read as unset — and then stage a command deleting it.
  const options = value && !field[2].includes(value) ? [value, ...field[2]] : field[2];
  for (const opt of options) {{
    const o = el("option", {{
      value: opt,
      text: opt === "" ? (fallback ? defaultLabel(fallback) : "(unset)") : opt,
    }});
    if (opt === (value || "")) o.setAttribute("selected", "selected");
    sel.append(o);
  }}
  return sel;
}}

// "default 1500" for a value, "defaults to \u2026" for a phrase: a default is
// sometimes another setting rather than a constant, and "default the router id"
// is not a sentence anybody wrote on purpose.
const defaultLabel = (v) => (v.includes(" ") ? "defaults to " + v : "default " + v);

// A field whose choices are exactly yes and no, however the table spells them.
function isBool(options) {{
  if (!options || options.length !== 3) return false;
  return options[0] === "" && options.includes("true") && options.includes("false");
}}

// A form that asks for everything asks for nothing in particular.
//
// `form` describes what an operator actually has to decide: `essential` is what
// is on screen from the start, and `byValue` narrows the rest by what they have
// already chosen — a bond has no VLAN id and a VLAN has no members, and showing
// both to everybody is why creating an interface felt like filling in a form
// about somebody else's network. Everything hidden is still there, one click
// away, and can be set later or never.
//
// `only` answers a different question, and it is the one "More settings" got
// wrong: not what is worth deciding first, but what this thing *has*. A plain
// ethernet link has no PPPoE password however deep you dig, and the appliance
// says so — `pppoe credentials require type = "pppoe"` — so a mask that offers
// one is describing a box that does not exist. Each entry names the values of
// `only.key` the setting applies to, or tests the whole form where it depends
// on more than one field. `only.watch` is what re-runs the test.
//
// Two rules keep this honest. A setting that is already set stays on screen
// whatever the type says, because hiding a value somebody configured is how a
// console starts lying about the box; and nothing becomes unreachable, because
// choosing the type reveals its settings and every type can be chosen.
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
  // A mask whose fields are one question asked about several things, laid out
  // as the table it already is. Sixteen dropdowns down a page under two
  // headings is the same information as nine rows and two columns, in twice
  // the room and without saying which of the sixteen is which — the labels
  // repeat ("BGP", "BGP") because the *heading* is carrying half the meaning,
  // and a heading is a long way from the ninth control under it.
  //
  // The field table is untouched: the matrix says how to fold it, and a key
  // like `import bgp` is found by its column and its row. It is the same
  // widgets, the same staging, the same `fieldLines` — only the arrangement.
  if (form && form.matrix) {{
    const spec = form.matrix;
    const at = new Map();
    fields.forEach((f, i) => at.set(f[0], i));
    const head = el("tr", {{}}, [
      el("th", {{ text: spec.corner || "" }}),
      ...spec.cols.map((c) => el("th", {{ text: c[1] }})),
    ]);
    const rows = el("tbody", {{}});
    for (const [rowKey, rowLabel] of spec.rows) {{
      const tr = el("tr", {{}}, [el("th", {{ class: "mtxrow", text: rowLabel }})]);
      for (const col of spec.cols) {{
        const i = at.get(col[0] + " " + rowKey);
        const cell = el("td", {{}});
        if (i === undefined) {{
          // Not a gap in the console: the appliance has no such setting, and a
          // blank box that stages nothing would be a worse way of saying so.
          cell.append(el("span", {{ class: "sub", text: "—" }}));
        }} else {{
          const hint = el("span", {{ class: "hint" }});
          const cellBox = el("label", {{ class: "field w-m" }}, [widgets[i], hint]);
          boxes[i] = cellBox;
          cell.append(cellBox);
          wireHint(fields[i], widgets[i], hint, values);
        }}
        tr.append(cell);
      }}
      rows.append(tr);
    }}
    // Every field needs a box, including the headings the table replaces: the
    // fold below walks both lists in step.
    fields.forEach((f, i) => {{ if (!boxes[i]) boxes[i] = el("div", {{}}); }});
    // Onto the mask, not into its first row: a row is a grid of 232px columns,
    // and a table dropped into one of them is a table 232px wide with the other
    // nine tenths of it behind a scrollbar.
    grid.append(el("div", {{ class: "tblwrap" }}, [
      el("table", {{ class: "mtx" }}, [el("thead", {{}}, [head]), rows]),
    ]));
    return {{ grid, widgets, more: null, refresh: () => {{}} }};
  }}
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
    // The unit belongs to the value, so where the box carries it the label
    // stops saying it too: "Refresh (s)" beside a box that already says `s` is
    // the same word twice.
    const unit = widgets[i].classList && widgets[i].classList.contains("num")
      ? (boundsOf(f[0]) || [])[2] : null;
    const label = el("span", {{
      text: unit && f[1].endsWith(" (" + unit + ")")
        ? f[1].slice(0, -(unit.length + 3)) : f[1],
    }});
    if (required && f[0] === required) label.append(el("span", {{ class: "req", text: "required" }}));
    const hint = el("span", {{ class: "hint" }});
    // A `<label>` around a set of `<label>`s makes every click in the dead
    // space tick the first checkbox — nested labels are invalid, and the outer
    // one adopts the first control in tree order. A switch is the same problem
    // the other way round: the only labelable thing inside it is the hidden
    // value, so a click on the row would open a dropdown nobody can see.
    const kind = (widgets[i].classList && widgets[i].className) || "";
    const owns = kind.includes("pick") || kind.includes("switch");
    // A set of tick boxes needs the run; a single figure does not, and neither
    // does a switch — two states take less room than a sentence, not more.
    const size = kind.includes("pick") || kind.includes("chips") ? " w-l"
      : kind.includes("switch") ? " w-auto"
      : (WIDTH[f[0]] ? " " + WIDTH[f[0]] : " w-m");
    const box = el(owns ? "div" : "label", {{ class: "field" + size }}, [label, widgets[i], hint]);
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
    const repaint = wireHint(f, widgets[i], hint, values);
    // A field filled from the appliance has nothing to say until the answer
    // comes back, and by then nobody is listening. This is how it gets a
    // second chance to say it.
    if (CHOICES[f[0]]) onChoices(CHOICES[f[0]], repaint);
  }});

  // Which fields are on screen right now. A form that gates by kind without
  // naming an `essential` few is not folded at all — it is the whole mask, with
  // the settings this kind of thing does not have left out.
  let showAll = !form || !form.essential;
  // Does this setting exist on the thing being edited at all?
  const applies = (key, now) => {{
    const rule = form && form.only && form.only.map[key];
    if (!rule) return true;
    if (typeof rule === "function") return !!rule(now, row);
    return rule.includes(now[form.only.key] || "");
  }};
  const apply = () => {{
    if (!form) return;
    const now = values();
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
      const set = !!(row && row[f[0]]) || !!(widgets[i].value && !defaultOf(f[0]));
      const on = set || ((showAll || visible.has(f[0])) && applies(f[0], now));
      boxes[i].classList.toggle("hidden", !on);
      if (on) headHasOne = true;
    }});
    if (lastHead) lastHead.classList.toggle("hidden", !headHasOne);
  }};
  // What the shape of the mask depends on. Both events: a kind is chosen from a
  // dropdown, and `dhcp` is typed into an address.
  const watched = new Set();
  if (form && form.byValue) watched.add(form.byValue.key);
  if (form && form.only) for (const k of (form.only.watch || [form.only.key])) watched.add(k);
  fields.forEach((f, i) => {{
    if (!widgets[i] || !watched.has(f[0])) return;
    for (const kind of ["change", "input"]) widgets[i].addEventListener(kind, apply);
  }});
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
    // A mask with nothing folded away has nothing to reveal.
    more: form && form.essential
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

// Settings the appliance cannot remove one at a time, and what it removes
// instead. A rule's schedule is three leaves of one thing — days, a start and
// an end — and the CLI has no `delete … schedule days`, because a window with
// no days is not a window. Emptying any of the three therefore stages `delete
// … schedule`, which is the command that exists; without this the console
// wrote one the appliance can only refuse, and the refusal took the rest of
// the batch with it.
const CLEARS = {{
  "schedule days": "schedule",
  "schedule start": "schedule",
  "schedule end": "schedule",
}};

// The commands an edit becomes: a value writes, an emptied field removes. The
// difference matters — leaving a field blank has to mean "no longer set", not
// "leave whatever was there".
function fieldLines(fields, widgets, path, before) {{
  const lines = [];
  const push = (line) => {{ if (!lines.includes(line)) lines.push(line); }};
  fields.forEach((f, i) => {{
    if (!widgets[i]) return;   // a heading writes nothing
    const v = (widgets[i].value || "").trim();
    const had = (before && before[f[0]]) || "";
    if (!v) {{
      if (had) push(`delete ${{path}} ${{CLEARS[f[0]] || f[0]}}`);
      return;
    }}
    if (v === had) return;
    // A repeatable setting *adds*. Editing "CN,RU" down to "CN" by setting the
    // new value would leave RU blocked and nothing on screen would say so, so
    // the list is cleared first and then written. Not `pick`: that one names a
    // setter the appliance *assigns* — a rule's open days are replaced by the
    // command that writes them — and clearing first would delete the schedule
    // this line is halfway through rewriting.
    if (f[3] && f[3] !== "pick" && had) push(`delete ${{path}} ${{f[0]}}`);
    // Some of them take the list in one command; others take one value per
    // command, and writing a comma into those is a refusal.
    if (f[3] === "each") {{
      for (const one of v.split(",").map((one) => one.trim()).filter(Boolean)) {{
        push(`set ${{path}} ${{f[0]}} ${{one}}`);
      }}
    }} else {{
      push(`set ${{path}} ${{f[0]}} ${{v}}`);
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
  fieldPath = path;
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
  foot.dataset.label = label;
  if (more) foot.append(more);
  box.append(foot);
  nameStageButtons();
}}

/// What each Stage button on the page commits.
///
/// A page that holds one mask needs no more than "Stage": there is nothing else
/// it could mean. A page that holds several writes several different nodes, and
/// three identical buttons down one scroll is a page where an operator cannot
/// tell what any of them will do — so on those, and only on those, the button
/// says the name of the block it belongs to.
///
/// Deferred, because the masks of a page are rendered one after another and the
/// first of them cannot yet see the others.
let namingStages = false;
function nameStageButtons() {{
  if (namingStages) return;
  namingStages = true;
  setTimeout(() => {{
    namingStages = false;
    for (const pane of document.querySelectorAll('[id^="view-"]')) {{
      // Only the section-wide masks. An object's own editor and its "New" panel
      // are opened deliberately, one at a time, and already say which object
      // they are about — renaming their buttons would take that away.
      const feet = [...pane.querySelectorAll(".maskfoot")]
        .filter((f) => f.dataset.label)
        .filter((f) => !f.closest(".tabpane") || !f.closest(".tabpane").classList.contains("hidden"));
      for (const foot of feet) {{
        const button = foot.querySelector(".btn.primary");
        if (!button) continue;
        button.textContent = feet.length > 1 ? "Stage " + foot.dataset.label : "Stage";
      }}
    }}
  }}, 0);
}}

// A container that holds a mask lays out nothing itself: the mask brings its own
// groups and columns, and a grid wrapped in a grid is two layouts fighting over
// the same fields.
function maskHost(box) {{
  box.classList.remove("grid");
  box.classList.add("maskhost");
}}

// The keys of a mask's first group.
//
// A mask may lead with fields that belong to no heading — EVPN's tunnel
// endpoint and encapsulation, the links intrusion detection watches — and those
// are its first group. Skipping to the first *heading* put exactly the settings
// somebody opened the page for behind "More settings" and left the rare ones on
// screen, which is the fold upside down.
function firstGroup(fields) {{
  const lead = [];
  for (const f of fields) {{
    if (f[0] === "#") break;
    lead.push(f[0]);
  }}
  if (lead.length) return lead;
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
  "auth-key", "secret", "passphrase", "macsec-key", "subscription-key",
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
  fieldPath = path;

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
      fieldPath = path;
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
  // Most objects are removed by deleting them. A few the appliance switches off
  // with a verb of its own — a DHCP server and a router advertisement are turned
  // on by one, so they are turned off by the other — and a console that spells
  // the same act a second way is a second grammar to keep in step.
  const off = o.off && o.off(row);
  const del = el("button", {{
    class: "btn danger", text: off ? off.label : "Delete",
    onclick: () => stage(
      off ? `${{off.label}} ${{o.noun.toLowerCase()}} ${{row.name}}`
          : `Delete ${{o.noun.toLowerCase()}} ${{row.name}}`,
      off ? off.lines : [`delete ${{path}}`]),
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
      if (node.classList.contains("tabpane")) continue;
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
  fieldPath = o.path("<n>");
  // No `nameHint`, no placeholder: "name" under a box labelled Name is the
  // label again, which is the one thing a placeholder must never be.
  const name = el("input", {{ placeholder: o.nameHint || "" }});
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

// The global block is the same posture minus the two settings that only mean
// something about a zone — whether that zone *is* the appliance, and the label
// somebody gave it — plus the one a zone cannot have: what happens to a packet
// the data plane cannot parse at all.
//
// Sharing the zone's table wholesale offered `local` and `description` here,
// and `set firewall global local true` is a path the appliance does not have.
// One touch of that field put a command in the batch that could only be
// refused — and a refusal is the whole batch's, so the changes staged beside it
// could not be applied either, until the operator worked out which of them was
// to blame. A console must not offer a setting the CLI has no home for.
const ZONE_ONLY = ["local", "description"];
const GLOBAL_POSTURE = POSTURE.filter((f) => !ZONE_ONLY.includes(f[0])).concat([
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
    // A zone had to be brought into being by naming it on an interface, which
    // is backwards for the one object the whole firewall is addressed by: rules
    // say `from wan`, so `wan` has to be creatable before anything can point at
    // it. `default-action` is required because a zone with no posture is the
    // one thing a firewall should never be talked into.
    form: FORMS.zone, required: "default-action",
    toggleId: "togglezone", toggleLabel: "New zone", addId: "addzonepanel",
    path: (n) => `firewall zone ${{n}}`,
    rows: [...overrides.values()].sort((a, b) => a.name.localeCompare(b.name)),
    badge: (r) => ({{ text: r["default-action"] || "inherits", cls: r["default-action"] || "" }}),
    empty: "No zones yet — create one, then give an interface its name.",
  }});
}}

// ---- NAT -----------------------------------------------------------------

// `source` and `translation` were never settings — the appliance answers them
// with "unknown set path", so filling either one failed the whole apply.
const SNAT = [
  ["zone", "Zone"], ["description", "Description"],
  // Deterministic CGNAT: how many ports each inside address gets, and where
  // the first block starts. Both are figures the appliance bounds and one of
  // them has a constant behind it, so both are stepped rather than typed.
  ["#", "Carrier-grade NAT"],
  ["cgnat-block-size", "Ports per host"],
  ["cgnat-base-port", "First port"],
  ["#", "Whether it is on"],
  ["disabled", "Disabled", ["", "true", "false"]],
];
const DNAT = [
  ["zone", "Zone"], ["proto", "Protocol", ["", "tcp", "udp"]],
  // The port the outside world knocks on, and the machine inside that answers.
  // The second offers this box's DHCP reservations — see [`reservedHosts`] for
  // why a lease is deliberately not among them.
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
  // Lists, and declared as such: the appliance *appends* each of these, so a
  // field that wrote one value at a time left the community an operator had
  // just removed still tagged on every route this box originates. `list` is
  // also what puts the well-known ones on the page as chips.
  ["#", "What it tags its own routes with"],
  ["community", "Communities", null, "list"],
  ["large-community", "Large communities", null, "list"],
  ["ext-community", "Extended communities", null, "list"],
  ["#", "How it behaves"],
  ["hold-time", "Hold time"], ["cluster-id", "Cluster ID"],
  // A3. The per-neighbour `flowspec` switch further down only negotiates the
  // address family — it learns the rules. This is what acts on them, and it is
  // separate because letting a peer drop traffic here is a different decision
  // from agreeing to hear about it.
  ["flowspec-enforce", "Enforce FlowSpec", ["", "true", "false"]],
  ["flowspec-min-prefix", "FlowSpec prefix floor"],
  // A count of equal-cost paths, not a yes/no — offering true/false made ECMP
  // unconfigurable and the refusal took the rest of the batch with it.
  ["multipath", "Multipath"],
  ["ebgp-require-policy", "Require policy", ["", "true", "false"]],
  // A confederation is one AS to the outside and several inside it, which is how
  // a large network runs iBGP without a full mesh or a reflector.
  //
  // These and the RPKI settings below write under `protocols bgp` like
  // everything above them — `confederation id` and `rpki rtr` are the commands
  // they already are. They were three masks with three Stage buttons on one
  // screen, and nothing on it said which button committed which half.
  ["#", "Confederation"],
  ["confederation id", "Confederation AS"],
  ["confederation member", "Member ASes", null, "list"],
  // Origin validation. Without an RTR server there is still the local table of
  // authorisations further down the page, which is why both are here.
  ["#", "Origin validation"],
  ["rpki rtr", "RTR server"], ["rpki rtr-refresh", "Refresh"],
  ["rpki reject-invalid", "Reject invalid", ["", "true", "false"]],
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
  // The unit is on the box, so the label stops saying it: "GTSM hops" beside a
  // figure already marked `hops` is the same word twice.
  ["ttl-security", "GTSM (hops)"],
  ["bfd", "BFD", ["", "true", "false"]],
  ["bfd-auth-type", "BFD authentication",
    ["", "simple", "keyed-md5", "meticulous-md5", "keyed-sha1", "meticulous-sha1"]],
  ["bfd-auth-key-id", "BFD key id"], ["bfd-auth-key", "BFD key"],
];
const BGP_AGGREGATE = [["summary-only", "Suppress more specifics", ["", "true", "false"]]];
const BGP_ROA = [["origin-as", "Origin AS"], ["max-length", "Maximum length"]];


// ---- IPsec ---------------------------------------------------------------

const IPSEC = [
  ["#", "The two ends"],
  ["local", "Local address"], ["remote", "Remote address"],
  ["#", "What goes through it"],
  // Bound to a link, the routing table decides and the subnets may be left
  // empty; unbound, they are the tunnel's whole reach.
  ["vti", "Bind to interface (route-based)"],
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
  // The pre-shared key is the second half of the same decision the private key
  // is, and the appliance mints both from the same word. Offering `generate`
  // beside one and not the other was the console making the optional layer of
  // post-quantum protection the one an operator has to produce by hand.
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
    off: (r) => ({{ label: "Turn off",
                   lines: [`set interface ${{r.name}} dhcp-server disable`] }}),
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
    off: (r) => ({{ label: "Turn off",
                   lines: [`set interface ${{r.name}} router-advert disable`] }}),
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
  zone: {{ essential: ["default-action", "block-icmp"] }},
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
  rule: {{
    essential: ["from", "to", "action", "proto", "port", "source", "destination"],
    only: RULE_ONLY,
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
     "macvlan", "macsec", "l2tpv3", "vti", "wireless", "wwan"]],
  ["mtu", "MTU"], ["mss", "Clamp TCP MSS"], ["ingress-limit", "Ingress limit (Mbit/s)"], ["mac", "MAC address"], ["hw-id", "Pin to MAC"],
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
  // Two different things called VLAN, which is why they were confusing under
  // one heading: *this* interface being a VLAN on a parent, and this interface
  // being a bridge (or a port on one) that filters VLANs. They are three
  // groups now, and a link is only asked the one it could answer.
  ["#", "This interface is a VLAN"],
  ["vlan", "VLAN id"],
  ["vlan-protocol", "Tag protocol", ["", "802.1q", "802.1ad"]],
  // The bridge's own switch. Its ports' tags are with the rest of what belongs
  // to a port, further down: one is set on the bridge and the others on each
  // member, and standing them under one heading is what made two different
  // things called VLAN read as one confusing setting.
  ["#", "VLAN filtering on this bridge"],
  ["vlan-aware", "Filter VLANs on this bridge", ["", "true", "false"]],
  ["#", "Tunnel endpoints"],
  ["local", "Local"], ["remote", "Remote"], ["key", "Key"], ["ttl", "TTL"],
  // Two kinds of link, not one setting with three fields: a MACVLAN takes a
  // mode and a MACsec device takes a key and a peer, and no link is both.
  ["#", "MACVLAN"],
  ["macvlan-mode", "MACVLAN mode", ["", "bridge", "private", "vepa", "passthru"]],
  ["#", "MACsec"],
  ["macsec-key", "MACsec key"], ["macsec-peer", "MACsec peer"],
  ["#", "PPPoE credentials"],
  ["pppoe username", "Username"], ["pppoe password", "Password"],
  ["pppoe service-name", "Service name"], ["pppoe ac-name", "Access concentrator"],
  ["pppoe mru", "MRU"],
  // Kernel behaviour that belongs to one link rather than to the box. Under
  // "More settings" because most links want none of it — but a multi-homed
  // firewall wants the ARP block, and the answer to "why does the peer have the
  // wrong MAC for us" is in here and nowhere else.
  ["#", "Cellular"],
  ["wwan apn", "APN"],
  ["wwan username", "Username"],
  ["wwan password", "Password"],
  ["wwan pin", "SIM PIN"],
  ["wwan ip-type", "IP type", ["", "ipv4", "ipv6", "ipv4v6"]],
  ["#", "Wireless"],
  ["wireless mode", "Role", ["", "access-point", "station"]],
  ["wireless ssid", "Network name"],
  ["wireless country", "Country"],
  ["wireless channel", "Channel"],
  ["wireless band", "Band", ["", "b", "g", "n", "a", "ac", "ax"]],
  ["wireless hide-ssid", "Hide the SSID", ["", "true", "false"]],
  ["wireless isolate-stations", "Isolate clients", ["", "true", "false"]],
  ["wireless max-stations", "Maximum clients"],
  ["wireless wpa mode", "WPA", ["", "wpa2", "wpa3", "wpa2+wpa3"]],
  ["wireless wpa passphrase", "Passphrase"],
  ["#", "NIC hardware"],
  ["ethernet speed", "Force link speed (Mbit/s)"],
  ["ethernet duplex", "Duplex", ["", "full", "half"]],
  ["ethernet rx-ring", "RX ring depth"],
  ["ethernet tx-ring", "TX ring depth"],
  ["ethernet rx-usecs", "RX coalescing (µs)"],
  ["ethernet tx-usecs", "TX coalescing (µs)"],
  ["ethernet adaptive-rx", "Adaptive RX coalescing", ["", "true", "false"]],
  ["ethernet adaptive-tx", "Adaptive TX coalescing", ["", "true", "false"]],
  ["#", "Bridge (on the bridge device)"],
  ["bridge stp", "Spanning tree", ["", "true", "false"]],
  ["bridge priority", "Bridge priority"],
  ["bridge hello-time", "Hello time (s)"],
  ["bridge max-age", "Max age (s)"],
  ["bridge forward-delay", "Forward delay (s)"],
  ["bridge ageing-time", "MAC ageing time (s)"],
  ["bridge igmp-snooping", "IGMP snooping", ["", "true", "false"]],
  ["bridge igmp-querier", "IGMP querier", ["", "true", "false"]],
  ["#", "As a port of a bridge"],
  ["bridge-port cost", "STP path cost"],
  ["bridge-port priority", "STP port priority"],
  ["bridge-port learning", "Learn MACs here", ["", "true", "false"]],
  ["vlan-tagged", "Tagged ids on this bridge port"],
  ["vlan-untagged", "Untagged id on this bridge port"],
  ["#", "Bond (on the bond device)"],
  ["bond hash-policy", "Hash policy",
    ["", "layer2", "layer2+3", "layer3+4", "encap2+3", "encap3+4"]],
  ["bond lacp-rate", "LACP rate", ["", "slow", "fast"]],
  ["bond min-links", "Minimum links"],
  ["bond primary", "Preferred member"],
  ["bond mii-interval", "Carrier check (ms)"],
  ["bond arp-interval", "ARP probe interval (ms)"],
  ["bond arp-target", "ARP probe targets", null, "each"],
  ["#", "Route-based IPsec"],
  ["vti-key", "Interface id (matched by the tunnel)"],
  ["#", "Port mirroring"],
  ["mirror-ingress", "Mirror arriving frames to"],
  ["mirror-egress", "Mirror leaving frames to"],
  ["#", "IPv4 on this link"],
  ["ip disable-forwarding", "Do not route IPv4 out", ["", "true", "false"]],
  ["ip proxy-arp", "Proxy ARP", ["", "true", "false"]],
  ["ip proxy-arp-pvlan", "Proxy ARP between private-VLAN ports", ["", "true", "false"]],
  ["ip arp-cache-timeout", "ARP cache timeout (s)"],
  ["ip arp-filter", "Only answer ARP for this link", ["", "true", "false"]],
  ["ip arp-accept", "Learn from gratuitous ARP", ["", "true", "false"]],
  ["ip arp-announce", "Announce from the target's subnet", ["", "true", "false"]],
  ["ip arp-ignore", "Ignore ARP for other links", ["", "true", "false"]],
  ["ip directed-broadcast", "Forward directed broadcasts", ["", "true", "false"]],
  ["#", "IPv6 on this link"],
  ["ipv6 disable-forwarding", "Do not route IPv6 out", ["", "true", "false"]],
  ["ipv6 no-link-local", "No automatic fe80:: address", ["", "true", "false"]],
  ["ipv6 dad-transmits", "DAD probes"],
  ["ipv6 accept-dad", "On DAD failure", ["", "0", "1", "2"]],
  ["#", "DHCP client (address dhcp)"],
  ["dhcp client-id", "Client id (option 61)", ["", "mac", "duid"]],
  ["dhcp duid", "Fixed DUID (with client-id duid)"],
  ["dhcp host-name", "Hostname (option 12)"],
  ["dhcp vendor-class-id", "Vendor class (option 60)"],
  ["dhcp user-class", "User class (option 77)"],
  ["dhcp no-default-route", "No default route from the lease", ["", "true", "false"]],
  ["dhcp default-route-distance", "Default-route metric"],
  ["dhcp reject", "Reject offers from", null, "each"],
  ["#", "DHCPv6 client (address6 dhcp)"],
  ["dhcpv6 duid", "Fixed DUID"],
  ["dhcpv6 rapid-commit", "Rapid commit", ["", "true", "false"]],
  ["dhcpv6 parameters-only", "Parameters only (no address)", ["", "true", "false"]],
  ["dhcpv6 no-release", "Do not RELEASE on link down", ["", "true", "false"]],
];

// Which links are ports of a bridge, and which of a VLAN-aware one.
//
// A port's spanning-tree cost and its VLAN membership are settings of the
// *port*, and the appliance refuses both anywhere else — "vlan-tagged/
// vlan-untagged require membership of a vlan-aware bridge" — so they are asked
// of a link some bridge names as a member, and of no other. Staged changes
// count: putting eth2 into br0 and then giving it a path cost is one piece of
// work, and a console that made it two would be arguing with itself.
function bridgeMembership() {{
  const kind = new Map(), members = new Map(), aware = new Map();
  const note = (name, leaf, value) => {{
    if (leaf === "type") kind.set(name, value);
    else if (leaf === "vlan-aware") aware.set(name, value);
    else if (leaf === "member") {{
      members.set(name, (members.get(name) || [])
        .concat(String(value).split(/[,\s]+/).filter(Boolean)));
    }}
  }};
  for (const l of lastLeaves) {{
    if (l.path[0] !== "interface" || l.path.length !== 3) continue;
    note(l.path[1], l.path[2], l.value);
  }}
  for (const entry of staged) {{
    for (const command of entry.cmds) {{
      const w = String(command).trim().split(/\s+/);
      if (w[0] !== "set" || w[1] !== "interface" || w.length !== 5) continue;
      note(w[2], w[3], w[4]);
    }}
  }}
  const ports = new Set(), tagged = new Set();
  for (const [name, list] of members) {{
    if (kind.get(name) !== "bridge") continue;
    for (const m of list) {{
      ports.add(m);
      if (aware.get(name) === "true") tagged.add(m);
    }}
  }}
  return {{ ports, tagged }};
}}

const isBridgePort = (now, row) =>
  !!row && bridgeMembership().ports.has(row.name);
const isVlanPort = (now, row) =>
  !!row && bridgeMembership().tagged.has(row.name);

// Every setting written under one word — `pppoe username`, `bridge stp` —
// belongs to the kind of link that word names. Read off the table rather than
// listed a second time, so a setting added there cannot be left ungated.
const ifaceFamily = (prefix, kinds) => Object.fromEntries(
  IFACE.filter((f) => f[0].startsWith(prefix + " ")).map((f) => [f[0], kinds]));

// The kernel tunnels. `key` is not on all of them: IPIP carries none, and the
// appliance says so rather than ignoring it.
const TUNNEL = ["gre", "ipip", "gretap", "l2tpv3"];
const KEYED_TUNNEL = ["gre", "gretap", "l2tpv3"];

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
  // What a link of this kind has at all — every line here is a refusal the
  // appliance already makes, so the mask asks for exactly what could be
  // committed. Before this, an ordinary ethernet port under "More settings"
  // was asked for a VLAN id, a bridge port's tags, a tunnel's endpoints, a
  // MACVLAN mode, a MACsec key and a PPPoE login, all at once.
  only: {{
    key: "type",
    // The address decides two families of their own: a DHCP client's options
    // are dead weight on a link with a static address.
    watch: ["type", "address", "address6"],
    map: {{
      // A parent is the link something rides on: a VLAN's trunk, a PPPoE
      // session's NIC, the interface a MACVLAN or MACsec device is made from.
      parent: ["", "pppoe", "macvlan", "macsec"],
      vlan: [""],
      "vlan-protocol": [""],
      member: ["bridge", "bond"],
      "bond-mode": ["bond"],
      "vlan-aware": ["bridge"],
      "vlan-tagged": isVlanPort,
      "vlan-untagged": isVlanPort,
      local: TUNNEL, remote: TUNNEL, ttl: TUNNEL, key: KEYED_TUNNEL,
      "macvlan-mode": ["macvlan"],
      "macsec-key": ["macsec"], "macsec-peer": ["macsec"],
      "vti-key": ["vti"],
      // A name pinned to a card by its MAC is a fact about a card. A bridge is
      // not one, and neither is a tunnel.
      "hw-id": [""],
      ...ifaceFamily("pppoe", ["pppoe"]),
      ...ifaceFamily("wwan", ["wwan"]),
      ...ifaceFamily("wireless", ["wireless"]),
      ...ifaceFamily("ethernet", [""]),
      ...ifaceFamily("bridge", ["bridge"]),
      ...ifaceFamily("bond", ["bond"]),
      ...ifaceFamily("bridge-port", isBridgePort),
      // "Only meaningful with address = dhcp", says the appliance's own model,
      // and the heading says it too — so the group appears when that is what
      // the address is.
      ...ifaceFamily("dhcp", (now) => (now.address || "").trim() === "dhcp"),
      ...ifaceFamily("dhcpv6", (now) => (now.address6 || "").trim() === "dhcp"),
    }},
  }},
}};

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
  "domain-group": "domain", "feed-group": "url", "user-group": "user",
  "mac-group": "mac", "interface-group": "interface",
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
// A directory. Simple bind as the user, so what is needed is where the accounts
// live and what names one.
const AAA_LDAP = [
  ["base-dn", "Base DN"], ["user-attribute", "Account attribute"],
  // Unset is `ldaps`, so it is on the list: a control with no way back to the
  // appliance's own answer makes the operator guess which of three it was.
  ["tls", "Transport", ["", "ldaps", "starttls", "none"]],
  ["port", "Port"], ["timeout", "Timeout"],
];
const AAA_RADIUS = [
  ["secret", "Shared secret"], ["port", "Port"], ["timeout", "Timeout (s)"],
];
const AAA_TACACS = [
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
    listId: "ldaplist", required: "base-dn", toggleId: "toggleldap",
    toggleLabel: "New directory", addId: "addldappanel", noun: "Directory",
    fields: AAA_LDAP, nameHint: "ldap.example.com",
    path: (n) => `system aaa ldap ${{n}}`,
    rows: entriesUnder(aaals, ["system", "aaa", "ldap"]),
    // The transport is the thing worth seeing at a glance: `none` means the
    // bind password crosses the wire in the clear.
    badge: (r) => (r.tls || "ldaps") === "none"
      ? {{ text: "no TLS", cls: "warn" }}
      : {{ text: r.tls || "ldaps" }},
    empty: "No directories configured.",
  }});
  renderObjects({{
    listId: "tacacslist", required: "secret", toggleId: "toggletacacs",
    toggleLabel: "New server", addId: "addtacacspanel", noun: "Server",
    fields: AAA_TACACS, nameHint: "10.0.0.49",
    path: (n) => `system aaa tacacs ${{n}}`,
    rows: entriesUnder(aaals, ["system", "aaa", "tacacs"]),
    // The secret is never a badge, exactly as with RADIUS.
    badge: (r) => r.secret ? {{ text: "port " + (r.port || 49) }}
                           : {{ text: "no secret", cls: "warn" }},
    empty: "No TACACS+ servers configured.",
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

  settingsPanel("svc-ids", SVC_IDS, fieldsOf(await leaves(), "services ids"),
                "services ids", "Detection");

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
// Twelve boxes at once for a resolver whose whole job, most days, is "ask
// these servers, answer on these links". The rest — what it will not forward,
// what it answers out of its own pocket, how long it keeps an answer — is real
// and is one click away.
const SVC_DNS = [
  ["#", "Where it asks, and who it answers"],
  ["upstream", "Upstream servers", null, "list"], ["serve-on", "Serve on", null, "list"],
  ["local-domain", "Local domain"],
  ["#", "What it will not do"],
  ["allow-from", "Allow queries from", null, "each"],
  ["dont-query", "Never forward", null, "each"],
  ["blocklist", "Blocklists", null, "each"],
  ["#", "What it answers itself"],
  ["host-override", "Host overrides", null, "each"],
  ["txt-record", "TXT records", null, "each"],
  ["#", "Privacy and caching"],
  // Setting this takes the plaintext servers above out of the resolver: they
  // become the proxy's bootstrap, answering the one question its own hostname
  // poses rather than every question.
  ["secure-upstream", "Encrypted upstreams", null, "each"],
  ["dnssec", "DNSSEC", ["", "no", "yes", "allow-downgrade"]],
  ["cache-size", "Cache size"], ["negative-ttl", "Negative TTL (s)"],
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
// The console configuring the console. TLS is on by default and the box mints
// its own certificate, so the reasons to touch this are: bring a certificate of
// your own, move the port, widen the bind — or turn TLS off, which only makes
// sense on loopback or behind a terminator that already speaks it.
const SVC_WEB = [
  ["enable", "Enabled", ["", "true", "false"]], ["port", "Port"],
  ["listen-address", "Listen address"],
  ["tls", "Serve HTTPS", ["", "true", "false"]],
  ["tls-cert", "Certificate chain (PEM)"],
  ["tls-key", "Private key (PEM)"],
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
  // No keyboard, locale or time zone here: those are `system` settings and had
  // been copied in, so touching one built `set services dyndns timezone …` —
  // a path the appliance does not have, and a refusal takes the whole batch
  // with it. They are on the System page, which is where they are written.
  ["login", "Login"], ["password", "Password"], ["interface", "Interface"],
];
const SVC_DHCPRELAY = [
  ["interface", "Interfaces", null, "list"],
  ["server", "Server (v4)", null, "list"], ["server6", "Server (v6)", null, "list"],
];
// The BNG role (C17). The subscriber list is objects rather than fields, so it
// gets its own panel below; these are the concentrator's own settings.
const SVC_PPPOE_SERVER = [
  ["interface", "Serve on"], ["local-address", "Gateway address"],
  ["pool-start", "First pool address"], ["max-sessions", "Max sessions"],
  ["dns", "Offer DNS", null, "list"],
  ["service-name", "Service name"], ["ac-name", "Concentrator name"],
  ["mtu", "Session MTU"],
];
// A subscriber of the concentrator above. `password` is a secret the appliance
// redacts on read, so the field is write-only in the ordinary way.
const PPPOE_USER = [
  ["password", "Password"], ["address", "Fixed address"],
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
// Intrusion detection (roadmap C11). Repeatable fields are `each`, because a
// second watched link or a second rule file is an addition, not a replacement.
const SVC_IDS = [
  ["interface", "Links to watch", null, "each"],
  ["ruleset", "Rule files", null, "each"],
  ["rule", "Rules", null, "each"],
  ["#", "What counts as inside"],
  ["home-net", "Home networks", null, "each"],
  ["#", "Blocking on an alert"],
  ["block-on-alert", "Block the source", ["", "true", "false"]],
  ["never-block", "Never block", null, "each"],
  ["block-severity", "Least severe that blocks"],
  ["block-duration", "How long a block lasts (s)"],
  ["sni-block", "Refuse these server names", null, "each"],
];
// Flow export (roadmap C12).
const SVC_FLOW = [
  ["collector", "Collector (host:port)"],
  ["interval", "Seconds between exports"],
  ["domain", "Observation domain id"],
];
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
  ["query-interval", "Query interval"],
  ["query-response-interval", "Response interval"],
  ["robustness", "Robustness"],
  // PIM writes under `protocols multicast` too: the keys carry the sub-node, so
  // a field here is the command it already is. Its own group, because it answers
  // a different question — the querier asks who on this segment is listening,
  // PIM decides which segment a group reaches at all — but not its own mask,
  // because a second Stage button beside the first says nothing about which of
  // them commits what.
  ["#", "Between segments (PIM-SM)"],
  ["pim enabled", "Route between segments", ["", "true", "false"]],
  ["pim rp-address", "Rendezvous point"],
  ["pim interface", "Speaks on", null, "each"],
  ["pim hello-interval", "Hello interval"],
  ["pim spt-threshold", "Source-tree threshold"],
];
// An interface either faces receivers or faces where the traffic comes from.
const MULTICAST_IFACE = [
  // The three the appliance takes, from MULTICAST_ROLES. `disabled` was offered
  // here and is not one of them: picking it produced a command that could only
  // be refused, and a refusal takes the rest of the batch with it.
  ["role", "Role", ["", "querier", "upstream", "downstream"]],
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

// What crosses between the protocols and the kernel, and which route map decides
// it. This is where a redistribution is actually filtered: a protocol's own
// `redistribute` says *that* it offers its routes, and these say which of them
// survive on the way in and on the way back out.
//
// Named by protocol on purpose — `import bgp` is the command — and the value is
// a route map, so the field offers the maps this box has rather than asking for
// one to be spelled from memory.
const REDIST_FILTERS = [
  ["#", "Coming in, before the routing table takes it"],
  ["import connected", "Connected"], ["import static", "Static"],
  ["import kernel", "Kernel"], ["import bgp", "BGP"],
  ["import ospf", "OSPFv2"], ["import isis", "IS-IS"],
  ["import rip", "RIP"], ["import ripng", "RIPng"], ["import babel", "Babel"],
  ["#", "Going back out to a protocol or to the kernel"],
  ["export kernel", "Kernel"], ["export bgp", "BGP"],
  ["export ospf", "OSPFv2"], ["export isis", "IS-IS"],
  ["export rip", "RIP"], ["export ripng", "RIPng"], ["export babel", "Babel"],
];
// One question — which route map does this go through — asked about nine route
// sources in two directions, so it is laid out as the table it is. Connected
// and static routes have no export cell because there is nothing to export
// them *to*: you send routes to a protocol, and neither of those is one.
const REDIST_FILTER_TABLE = {{
  matrix: {{
    corner: "Route source",
    cols: [["import", "Coming in"], ["export", "Going back out"]],
    rows: [
      ["connected", "Connected"], ["static", "Static"], ["kernel", "Kernel"],
      ["bgp", "BGP"], ["ospf", "OSPFv2"], ["isis", "IS-IS"],
      ["rip", "RIP"], ["ripng", "RIPng"], ["babel", "Babel"],
    ],
  }},
}};
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
  ["match protocol", "Protocol",
    ["", "connected", "static", "kernel", "bgp", "ospf", "isis", "rip", "babel"]],
  ["match metric-ge", "Metric ≥"],
  ["match metric-le", "Metric ≤"],
  ["#", "What it changes"],
  ["set next-hop", "Next hop"],
  ["set metric", "Metric"],
  ["set add-metric", "Metric delta"],
  ["set preference", "Preference"],
  // The first replaces the set and the second adds to it — the appliance's own
  // distinction — so one is a `pick` (written whole, no clearing first) and the
  // other a `list` (cleared, then written). Both offer the well-known names.
  ["set community", "Communities", null, "pick"],
  ["set add-community", "Add community", null, "list"],
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
  // Where the box is and how its console is typed on. The time zone is the one
  // an operator notices: every log line and every certificate date is read
  // through it, and a box left on UTC is read wrong rather than not at all.
  ["timezone", "Time zone"],
  ["keyboard", "Console keyboard"],
  ["locale", "Locale"],
  // The port somebody reaches for when the network this box manages is the
  // thing that is broken. The speed is a closed set and a short one — a serial
  // console runs at one of five rates and has done for thirty years — so it is
  // the one of these four that can be a dropdown outright.
  ["console device", "Serial console"],
  ["console speed", "Console speed",
   ["", "9600", "19200", "38400", "57600", "115200"]],
  ["commit-revisions", "Revisions kept"],
  // The History view tells an operator to turn this on here, so it has to be
  // here. It was not: the console could read the history and not start it.
  ["metrics enable", "Keep a history", ["", "true", "false"]],
];
const SYS_UPDATE = [
  ["url", "Default channel URL"], ["public-key", "Signing key"],
  // Typed rather than picked on purpose: the channel to use may be the one
  // about to be defined in the list below, and a picker of what exists cannot
  // say what is about to.
  ["channel", "Active channel"],
];
// One named update channel. Each carries its OWN signing key — a channel is
// only as trustworthy as the key that vouches for it — and, for a subscription
// channel, the entitlement (a secret: listed as "set", never as its value).
const UPDATE_CHANNEL = [
  ["url", "Channel URL"], ["public-key", "Signing key"],
  ["subscription-key", "Subscription key"],
];


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
  // No "(ms)" on either label: the value carries its own unit — `5ms`, `100us`
  // — because tc does, and a label naming one unit beside a box that takes
  // several is the console telling the operator something untrue.
  ["target", "Target"], ["interval", "Interval"], ["limit", "Queue limit"],
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

  const lists = entriesWithStaged(entriesUnder(ls, ["policy", "prefix-list"]), ["policy", "prefix-list"]);
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

  const maps = entriesWithStaged(entriesUnder(ls, ["policy", "route-map"]), ["policy", "route-map"]);
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
  renderObjects({{
    listId: "upchanlist", required: "url", toggleId: "toggleupchan",
    toggleLabel: "New channel", addId: "addupchanpanel", noun: "Channel",
    fields: UPDATE_CHANNEL, nameHint: "enterprise",
    path: (n) => `update channel ${{n}}`,
    rows: entriesUnder(ls, ["update", "channel"]),
    // What matters at a glance: whether this channel is the active one, and
    // whether it can work at all. The subscription key is never a badge.
    badge: (r) => !r.url ? {{ text: "no URL", cls: "warn" }}
      : (fieldsOf(ls, "update").channel === r.name ? {{ text: "active" }}
                                                   : {{ text: "available" }}),
    empty: "No named channels — the default URL above is the channel.",
  }});
  await showInto("subshow", "/api/v1/show/subscription");
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
  for (const [box, fields, path, label, shape] of [
    ["igp-ospf", IGP_OSPF, "protocols ospf", "OSPFv2"],
    ["igp-ospf3", IGP_OSPF3, "protocols ospf3", "OSPFv3"],
    ["igp-isis", IGP_ISIS, "protocols isis", "IS-IS"],
    ["igp-rip", IGP_RIP, "protocols rip", "RIP"],
    ["igp-ripng", IGP_RIPNG, "protocols ripng", "RIPng"],
    ["igp-babel", IGP_BABEL, "protocols babel", "Babel"],
    ["igp-bfd", IGP_BFD, "protocols bfd", "BFD"],
    ["bgpglobal", BGP_GLOBAL, "protocols bgp", "BGP router settings"],
    ["mcastform", MULTICAST, "protocols multicast", "Multicast routing"],
    // Both halves write under `protocols`, and their keys carry which half —
    // `import bgp`, `export kernel` — so one panel is one node.
    ["redistfilters", REDIST_FILTERS, "protocols", "Route filters", REDIST_FILTER_TABLE],
  ]) {{
    settingsPanel(box, fields, fieldsOf(ls, path), path, label, shape);
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
    filters: [["filtershow", "/api/v1/show/ip/route"]],
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
    ["svc-web", SVC_WEB, "services web", "Web console"],
    ["svc-snmp", SVC_SNMP, "services snmp", "SNMP"],
    ["svc-lldp", SVC_LLDP, "services lldp", "LLDP"],
    ["svc-mdns", SVC_MDNS, "services mdns", "mDNS reflector"],
    ["svc-dyndns", SVC_DYNDNS, "services dyndns", "Dynamic DNS"],
    ["svc-dhcprelay", SVC_DHCPRELAY, "services dhcp-relay", "DHCP relay"],
    ["svc-pppoeserver", SVC_PPPOE_SERVER, "services pppoe-server", "PPPoE server"],
    ["svc-portal", SVC_PORTAL, "services portal", "Captive portal"],
    ["svc-portmap", SVC_PORTMAP, "services port-mapping", "Port mapping"],
    ["svc-alerts", SVC_ALERTS, "services alerts", "Alerts"],
    ["svc-alertmail", SVC_ALERTMAIL, "services alerts mail", "Alert mail"],
    ["svc-flow", SVC_FLOW, "services flow-export", "Flow export"],
  ];
  for (const [box, fields, path, label] of flat) {{
    settingsPanel(box, fields, under(path), path, label);
  }}

  renderObjects({{
    listId: "pppoeusers", required: "password", toggleId: "togglepppoeuser",
    toggleLabel: "New subscriber", addId: "addpppoeuserpanel", noun: "Subscriber",
    fields: PPPOE_USER, nameHint: "alice",
    path: (n) => `services pppoe-server user ${{n}}`,
    rows: entriesUnder(ls, ["services", "pppoe-server", "user"]),
    badge: (r) => r.address ? {{ text: r.address }} : {{ text: "from pool" }},
    empty: "No subscribers configured.",
  }});
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

// EVPN. The identity first, then the two object kinds.
// The three that make this box a VTEP lead the mask, and the rest are grouped
// by what they are about. The heading here used to read "More settings", which
// is the name of the *button* that reveals it — a page with a heading and a
// control of the same name says nothing about either and reads as a mistake.
const EVPN = [
  ["vtep-ip", "Tunnel endpoint address"],
  ["underlay-interface", "Underlay link"],
  ["encapsulation", "Encapsulation", ["", "vxlan", "geneve"]],
  ["#", "The tunnel it builds"],
  ["udp-port", "UDP port"],
  ["mtu", "Underlay MTU"],
  ["#", "SRv6, where the underlay carries segments instead"],
  ["srv6-locator", "SRv6 locator"],
  ["srv6-source", "SRv6 source address"],
  ["srv6-peer", "Accept decap from", null, "each"],
];
const EVPN_INSTANCE = [
  ["evi", "Instance id"],
  ["vni", "VNI"],
  ["interface", "Ports on this segment", null, "each"],
  ["#", "Route policy"],
  ["rd", "Route distinguisher"],
  ["rt-import", "Import targets", null, "each"],
  ["rt-export", "Export targets", null, "each"],
  ["advertise-mac", "Announce these MACs", null, "each"],
];
const EVPN_IPVRF = [
  ["l3-vni", "L3 VNI"],
  ["advertise-prefix", "Originate these prefixes", null, "each"],
  ["#", "Route policy"],
  ["rd", "Route distinguisher"],
  ["rt-import", "Import targets", null, "each"],
  ["rt-export", "Export targets", null, "each"],
  ["router-mac", "Router MAC"],
];

async function refreshEvpn() {{
  const ls = await leaves();
  settingsPanel("evpnform", EVPN, fieldsOf(ls, "evpn"), "evpn", "This box");
  renderObjects({{
    listId: "evilist", toggleId: "toggleevi", toggleLabel: "New segment",
    addId: "addevipanel", noun: "Segment", fields: EVPN_INSTANCE, nameHint: "tenant-a",
    path: (n) => `evpn instance ${{n}}`,
    rows: entriesUnder(ls, ["evpn", "instance"]),
  }});
  renderObjects({{
    listId: "ipvrflist", toggleId: "toggleipvrf", toggleLabel: "New tenant",
    addId: "addipvrfpanel", noun: "Tenant", fields: EVPN_IPVRF, nameHint: "blue",
    path: (n) => `evpn ip-vrf ${{n}}`,
    rows: entriesUnder(ls, ["evpn", "ip-vrf"]),
  }});
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
  chip: '<rect x="7" y="7" width="10" height="10" rx="1"/><path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4"/>',
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
  {{ g: "Overview", i: "gauge", items: [
    {{ v: "dashboard", t: "Dashboard", i: "gauge" }},
    {{ v: "history", t: "History", i: "chart" }},
  ]}},
  {{ g: "Policy", i: "shield", items: [
    {{ v: "rules", t: "Firewall rules", i: "shield" }},
    {{ v: "zones", t: "Zones", i: "zones" }},
    {{ v: "groups", t: "Groups", i: "layers" }},
    {{ v: "nat", t: "NAT", i: "swap" }},
    {{ v: "synproxy", t: "SYN protection", i: "pulse" }},
  ]}},
  {{ g: "Network", i: "address", items: [
    {{ v: "interfaces", t: "Interfaces", i: "address" }},
    // Not `address` again: two pages of a category wearing one glyph is a strip
    // read by position rather than by sight.
    {{ v: "dhcp", t: "DHCP", i: "list" }},
    {{ v: "qos", t: "Traffic shaping", i: "gauge" }},
    {{ v: "lb", t: "Load balancer", i: "swap" }},
  ]}},
  // Everything that decides where a packet goes next, in one place. Static
  // routes, one exterior protocol, six interior ones, the detector they share,
  // the policy that filters between them and the uplink selection on top — an
  // operator chasing a route should not have to know which of those answered.
  // Every protocol is named in the rail: a box that speaks seven of them and
  // shows one is a box an operator will assume cannot do the other six.
  {{ g: "Routing", i: "globe", items: [
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
    {{ v: "routing", tab: "vrf",    t: "VRFs", i: "zones" }},
    {{ v: "routing", tab: "filters", t: "Route filters", i: "list" }},
    {{ v: "routing", tab: "table",  t: "Routing table", i: "list" }},
    {{ v: "routepolicy", tab: "prefix", t: "Prefix lists", i: "layers" }},
    {{ v: "routepolicy", tab: "maps", t: "Route maps", i: "filter" }},
    {{ v: "routepolicy", tab: "pbr", t: "Policy routing", i: "route" }},
    {{ v: "wan", t: "Multi-WAN", i: "swap" }},
  ]}},
  {{ g: "Security", i: "lock", items: [
    {{ v: "ipsec", t: "IPsec", i: "lock" }},
    {{ v: "wireguard", t: "WireGuard", i: "key" }},
    {{ v: "openconnect", t: "Remote access", i: "lock" }},
    {{ v: "pki", t: "Authorities", i: "lock" }},
    {{ v: "certs", t: "Certificates", i: "file" }},
    {{ v: "ids", t: "Intrusion detection", i: "bug" }},
    {{ v: "capture", t: "Packet capture", i: "search" }},
  ]}},
  {{ g: "Overlay", i: "layers", items: [
    {{ v: "evpn", t: "EVPN", i: "layers" }},
  ]}},
  {{ g: "Services", i: "swap", items: [
    {{ v: "services", tab: "resolution", t: "DNS and time", i: "layers" }},
    {{ v: "services", tab: "management", t: "Management access", i: "key" }},
    {{ v: "services", tab: "addressing", t: "Addressing", i: "address" }},
    {{ v: "services", tab: "publishing", t: "Publishing", i: "swap" }},
    {{ v: "services", tab: "notification", t: "Logging and alerts", i: "bug" }},
  ]}},
  {{ g: "System", i: "chip", items: [
    {{ v: "system", t: "System", i: "gauge" }},
    {{ v: "ha", t: "High availability", i: "layers" }},
    {{ v: "users", t: "Administrators", i: "key" }},
    {{ v: "config", t: "Revisions", i: "file" }},
    {{ v: "stack", t: "Stack", i: "layers" }},
  ]}},
];

// The panes a divided view is made of, and the config node each one owns.
//
// The strip above the heading lists these as ordinary pages of the category, so
// this table is what keeps the two agreeing: one place says what the parts are,
// and a part added here appears there. The name is the name the strip prints —
// a destination has one, and a page that was "Filters" in one table and "Route
// filters" in the other was one page wearing two.
const TABS = {{
  routing: [
    {{ k: "static", t: "Static routes", n: "protocols static" }},
    {{ k: "bgp",    t: "BGP",     n: "protocols bgp" }},
    {{ k: "ospf",   t: "OSPFv2",  n: "protocols ospf" }},
    {{ k: "ospf3",  t: "OSPFv3",  n: "protocols ospf3" }},
    {{ k: "isis",   t: "IS-IS",   n: "protocols isis" }},
    {{ k: "rip",    t: "RIP",     n: "protocols rip" }},
    {{ k: "ripng",  t: "RIPng",   n: "protocols ripng" }},
    {{ k: "babel",  t: "Babel",   n: "protocols babel" }},
    {{ k: "bfd",    t: "BFD",     n: "protocols bfd" }},
    {{ k: "multicast", t: "Multicast", n: "protocols multicast" }},
    {{ k: "vrf",    t: "VRFs",    n: "protocols vrf" }},
    {{ k: "filters", t: "Route filters", n: ["protocols import", "protocols export"] }},
    {{ k: "table",  t: "Routing table" }},
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

// Farbe und Symbol der Live-Gruppen. Die Rust-Tabelle, die sie aufzählt, soll
// nichts über ihr Aussehen wissen -- deshalb hier, nach Namen nachgeschlagen.
const NAVMETA = {{
  Firewall:    ["shield"],
  NAT:         ["swap"],
  Network:     ["address"],
  Routing:     ["globe"],
  Security:    ["lock"],
  VPN:         ["key"],
  Diagnostics: ["bug"],
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

// A divided view shows one of its panes. Which one is a navigation question,
// and it is answered in exactly one place — the strip above the heading, which
// lists this category's pages whether they are separate views or panes of one.
// A second row of buttons saying the same thing was two navigations for one
// decision, and an operator could not tell which of them they were "in".
function renderTabs(v) {{
  const cur = currentTab(v);
  if (!cur) return;
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
    // A tab may stand for more than one node — the route filters are two — and
    // a mark on either is a mark on the tab.
    const nodes = it.n ? [].concat(it.n) : [];
    if (nodes.some((n) => ls.some((l) => l.node === n))) marks.add(it.k);
  }}
  tabMarks[v] = marks;
  // The marks live on the strip, which is the one navigation there is.
  renderSectionStrip();
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
  [["services", "pppoe-server"], "services:addressing"],
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

// Every place the palette can take you, flattened from the two registries the
// rail is built from: the editable views in `SECTIONS`, and the live panels in
// `NAV`. Each carries the same `run` the rail's own click does — `goto` for a
// view, the panel swap for a look — so the palette is a second door onto one
// activation, never a parallel one that could drift.
function paletteItems() {{
  const out = [];
  for (const group of SECTIONS) {{
    for (const item of group.items) {{
      const key = item.tab ? item.v + ":" + item.tab : item.v;
      out.push({{ t: item.t, g: group.g, run: () => goto(key) }});
    }}
  }}
  for (const group of NAV) {{
    for (const item of group.items) {{
      out.push({{ t: item.t, g: group.g, run: () => {{ view = "panel"; panel = item; refresh(); }} }});
    }}
  }}
  return out;
}}

let palItems = [];   // what the query currently matches
let palSel = 0;      // the row the arrows and Enter act on

function renderPalette() {{
  const q = $("paletteq").value.trim().toLowerCase();
  const all = paletteItems();
  // Substring over the page's own name and its category — enough to find a page
  // you can name, and nothing an operator has to learn the ranking of.
  palItems = q ? all.filter((e) => (e.t + " " + e.g).toLowerCase().includes(q)) : all;
  if (palSel >= palItems.length) palSel = Math.max(0, palItems.length - 1);
  const list = $("palettelist");
  list.textContent = "";
  if (!palItems.length) {{
    list.append(el("div", {{ class: "palempty", text: "No page matches" }}));
    return;
  }}
  palItems.forEach((e, idx) => {{
    const b = el("button", {{ class: "palitem" + (idx === palSel ? " on" : ""),
                             onclick: () => runPalette(idx) }});
    b.setAttribute("role", "option");
    b.setAttribute("aria-selected", String(idx === palSel));
    b.append(el("span", {{ class: "palt", text: e.t }}),
             el("span", {{ class: "palg", text: e.g }}));
    list.append(b);
  }});
}}

function scrollPaletteSel() {{
  const on = $("palettelist").querySelector(".palitem.on");
  if (on) on.scrollIntoView({{ block: "nearest" }});
}}

function runPalette(idx) {{
  const e = palItems[idx];
  if (!e) return;
  closePalette();
  e.run();
}}

function openPalette() {{
  const dlg = $("palette");
  if (dlg.open) return;
  $("paletteq").value = "";
  palSel = 0;
  renderPalette();
  dlg.showModal();
  $("paletteq").focus();
}}

function closePalette() {{
  const dlg = $("palette");
  if (dlg.open) dlg.close();
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
  qos: "Shaping belongs on the link that is actually congested, on the way out. Set the bandwidth slightly below what the line really carries: the point is to hold the queue here, where it can be managed, instead of in the modem, where it cannot.",
  lb: "Virtual addresses in front of backend pools.",
  routing: "Everything that decides where a packet goes next.",
  evpn: "One tenant network across several boxes: BGP carries who is where — a MAC learned here is announced to the others — and the data plane carries the frames toward whichever box announced the destination. Neither half is any use alone, so both are set here.",
  "routing:ospf": "The interior protocol most networks are built on: a link-state view of one area, or several joined at this box. It is off until it is given an interface to speak on.",
  "routing:ospf3": "OSPF for IPv6 — a separate protocol with its own adjacencies, not an address family of the one beside it. Running both is normal.",
  "routing:isis": "Link-state routing that carries both address families over one set of adjacencies. The system ID and area are what an adjacency is formed on, so they are set before an interface is added.",
  "routing:rip": "Distance-vector, and bounded to fifteen hops by design. It is here for the networks that still speak it, not as a first choice.",
  "routing:ripng": "RIP for IPv6, with the same reach and the same limits.",
  "routing:babel": "Distance-vector built for links that come and go — wireless, and meshes where the cost of a path is not the number of hops.",
  "routing:bfd": "Sub-second failure detection the protocols beside it subscribe to with their own bfd field. On its own it detects nothing.",
  "routing:multicast": "Multicast is not forwarded until this box is told to listen for the reports that say who wants a group. IGMP is the IPv4 half, MLD the IPv6 one, and an interface either faces receivers or faces the source.",
  "routing:vrf": "A separate routing table with its own interfaces, so two tenants can use the same addresses without meeting. Route targets are what let something deliberately cross between them.",
  "routing:filters": "Which routes cross between the protocols and this box's routing table, and which route map decides. A protocol's own redistribution offers its routes; these say which of them are taken, and which go back out.",
  "routing:table": "What the protocols above actually agreed on. A route is here once however many of them offered it — this is the answer, not the argument.",
  "routing:static": "Routes written by hand. They win over anything a protocol learns, which is what makes them useful and what makes a forgotten one hard to find.",
  "routing:bgp": "The exterior protocol: who this appliance is to another network, the neighbours it says it to, and what came of that. A neighbour without a remote AS is not a session.",
  "services:resolution": "Answering names, and agreeing what time it is. Each is off until it is given something to do — staging a field and committing is what starts it, and clearing the fields is what stops it.",
  "services:management": "How this box is reached and read from outside itself. Every one of these is a way in or a way out, and none of them should be listening on an untrusted zone.",
  "services:addressing": "Addresses and names for the segments behind this box — relayed to a server elsewhere, reflected across segments, or published upstream.",
  "services:publishing": "What this box puts in front of something else: a name terminated here, a broadcast carried across a segment boundary, a guest held at a login, a port an inside host asked for.",
  "services:notification": "Where the appliance speaks up, and who hears it. An alert is sent when a watched unit fails; the journal is forwarded continuously, whether or not anything is wrong.",
  history: "What the box looked like before now. Live counters cannot say whether this was also happening at three in the morning last Tuesday — and a gap in a line is a gap in the record, drawn as one rather than joined up.",
  routepolicy: "Prefix lists and route maps — what is accepted, and what is changed.",
  "routepolicy:prefix": "Named sets of prefixes a route map or a neighbour filter points at. Rules are read in sequence order, ge and le widen one to a range of lengths, and a list exists once it has a rule.",
  "routepolicy:maps": "What is accepted, and what is changed on the way through. Each rule matches and then sets; the map's default decides what happens to a route no rule matched.",
  "routepolicy:pbr": "Traffic sent by where it came from, over which link and to which port, rather than by where it is going. That is how a guest network leaves by the cheap uplink while everything else takes the good one.",
  wan: "Which uplink carries new connections, and what happens when one fails.",
  ipsec: "Site-to-site IKEv2 tunnels.",
  wireguard: "Site-to-site WireGuard interfaces and their peers.",
  openconnect: "The road-warrior server: a client connects with a username and password and lands in the zone named below. IPsec and WireGuard are site-to-site — this is the one people carry.",
  pki: "Local certificate authorities.",
  certs: "Issued certificates and what they are used for.",
  ids: "Detection, and what an alert is allowed to do about it.",
  capture: "See the wire itself: never more than 500 packets or 60 seconds, headers only, and nothing written to disk. A capture that finds nothing is an answer too.",
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

  // Searching is the one time the rail lists single sections: a hit has to be
  // clickable where it was found, and making the operator first guess the
  // category it lives under would defeat the search.
  if (filter) {{
    for (const group of SECTIONS) {{
      const items = group.items.filter((i) => i.t.toLowerCase().includes(filter));
      if (!items.length) continue;
      const box = el("div", {{ class: "group" }}, [el("span", {{ class: "grp", text: group.g }})]);
      for (const item of items) {{
        const k = item.tab ? item.v + ":" + item.tab : item.v;
        const b = navButton(item.t, item.i, () => goto(k), k);
        if (k === key && !panel) b.classList.add("on");
        box.append(b);
      }}
      nav.append(box);
    }}
    for (const group of NAV) {{
      const items = group.items.filter((i) => i.t.toLowerCase().includes(filter));
      if (!items.length) continue;
      const box = el("div", {{ class: "group" }}, [el("span", {{ class: "grp", text: group.g }})]);
      for (const item of items) {{
        const b = navButton(item.t, "chart", () => {{ view = "panel"; panel = item; refresh(); }}, item.p);
        b.dataset.path = item.p;
        box.append(b);
      }}
      nav.append(box);
    }}
    if (!nav.children.length) {{
      nav.append(el("div", {{ class: "group" }}, [
        el("span", {{ class: "grp", text: "No section matches" }}),
        el("button", {{
          class: "navitem", text: "Clear the search",
          onclick: () => {{ $("navsearch").value = ""; buildNav(); renderMatches(); }},
        }}),
      ]));
    }}
    return;
  }}

  // Otherwise the rail is the categories and nothing else. A router's console
  // is opened to reach one area and work there; a rail that names every one of
  // sixty-nine pages at once makes the operator read the whole product before
  // they can start. The category's own pages are one strip away, in the content
  // where the work is -- so nothing is further than two clicks, and the rail
  // stays short enough to hold a system summary underneath it.
  const cfg = el("div", {{ class: "group" }}, [el("span", {{ class: "grp", text: "Configure" }})]);
  for (const group of SECTIONS) {{
    const first = group.items[0];
    const k = first.tab ? first.v + ":" + first.tab : first.v;
    const b = navButton(group.g, group.i || "list", () => goto(k), "cat:" + group.g);
    if (group.c) b.style.setProperty("--cat", group.c);
    b.classList.add("cat");
    if (!panel && group.items.some((i) => (i.tab ? i.v + ":" + i.tab : i.v) === key)) b.classList.add("on");
    cfg.append(b);
  }}
  nav.append(cfg);

  const live = el("div", {{ class: "group" }}, [el("span", {{ class: "grp", text: "Look" }})]);
  for (const group of NAV) {{
    const [ic] = NAVMETA[group.g] || ["chart"];
    const first = group.items[0];
    const b = navButton(group.g, ic, () => {{ view = "panel"; panel = first; refresh(); }}, "live:" + group.g);
    b.classList.add("cat");
    if (panel && group.items.some((i) => i.p === panel.p)) b.classList.add("on");
    live.append(b);
  }}
  nav.append(live);
}}

// Which category the current page belongs to, and what else is in it. The rail
// names the category; this is what turns that into the pages themselves.
function currentCategory() {{
  const key = viewKey();
  if (panel) {{
    for (const g of NAV) if (g.items.some((i) => i.p === panel.p))
      return {{ name: g.g, live: true, items: g.items.map((i) => ({{ t: i.t, go: () => {{ view = "panel"; panel = i; refresh(); }}, on: i.p === panel.p }})) }};
    return null;
  }}
  for (const g of SECTIONS) {{
    if (!g.items.some((i) => (i.tab ? i.v + ":" + i.tab : i.v) === key)) continue;
    return {{ name: g.g, colour: g.c, items: g.items.map((i) => {{
      const k = i.tab ? i.v + ":" + i.tab : i.v;
      // A page that is a pane of a divided view can say whether it already
      // carries configuration: seven protocols, and the question worth
      // answering before opening any of them is which of them is running.
      const marked = !!(i.tab && (tabMarks[i.v] || new Set()).has(i.tab));
      return {{ t: i.t, i: i.i, go: () => goto(k), on: k === key, marked }};
    }}) }};
  }}
  return null;
}}

// The one navigation inside a category: its pages, whichever of them are
// separate views and whichever are panes of a divided one. It carries the marks
// the rail cannot — an icon per page, and a dot on the ones already configured.
function renderSectionStrip() {{
  const host = $("sectionstrip");
  if (!host) return;
  host.textContent = "";
  const cat = currentCategory();
  // One page in a category needs no strip: a chooser with a single choice is
  // furniture, not navigation.
  if (!cat || cat.items.length < 2) return;
  if (cat.colour) host.style.setProperty("--cat", cat.colour);
  for (const it of cat.items) {{
    const b = el("button", {{ class: "secitem" + (it.on ? " on" : ""), onclick: it.go }});
    if (it.i) b.append(icon(it.i));
    b.append(el("span", {{ text: it.t }}));
    if (it.marked) b.append(el("span", {{ class: "live", title: "configured" }}));
    host.append(b);
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
  renderSectionStrip();
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
  if (view === "evpn") return refreshEvpn();
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
  const name = who || "management token";
  const parts = name.split(/[^a-zA-Z0-9]+/).filter(Boolean);
  const init = ((parts[0] || "m")[0] + (parts[1] ? parts[1][0] : (parts[0] || "mt")[1] || "")).toUpperCase();
  if ($("whoname")) $("whoname").textContent = name;
  if ($("whoinit")) $("whoinit").textContent = init;
  if ($("userchip")) $("userchip").title = who ? "signed in as " + who : "signed in with the machine token";
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
  if (readOnly && !gateObserver) {{
    gateObserver = new MutationObserver(() => gateWrites());
    gateObserver.observe(document.querySelector("main") || document.body,
      {{ childList: true, subtree: true }});
  }}
  gateWrites();
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

// The palette: opened from the rail hint or by Cmd/Ctrl-K anywhere, filtered as
// you type, walked with the arrows, taken with Enter, dismissed with Esc (the
// dialog's own cancel closes it, so nothing here has to catch Escape).
$("palettehint").onclick = openPalette;
$("paletteq").oninput = () => {{ palSel = 0; renderPalette(); }};
$("paletteq").onkeydown = (e) => {{
  if (e.key === "ArrowDown") {{
    e.preventDefault();
    palSel = Math.min(palSel + 1, palItems.length - 1);
    renderPalette(); scrollPaletteSel();
  }} else if (e.key === "ArrowUp") {{
    e.preventDefault();
    palSel = Math.max(palSel - 1, 0);
    renderPalette(); scrollPaletteSel();
  }} else if (e.key === "Enter") {{
    e.preventDefault();
    runPalette(palSel);
  }}
}};
document.addEventListener("keydown", (e) => {{
  if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {{
    e.preventDefault();
    $("palette").open ? closePalette() : openPalette();
  }}
}});
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
// The badge is the review's doorway: it brings the staged card into view, so
// the exact commands are read before anything is applied.
$("stagedbadge").onclick = () => {{
  if (!staged.length) return;
  $("stagedcard").scrollIntoView({{ behavior: "smooth", block: "start" }});
}};
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
wireToggle("togglezone", "addzonepanel", "New zone");
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
// `oninput`, not `onchange`: a text field only fires change when it is left,
// so naming a map and reaching straight for "New rule" -- the path an operator
// actually takes -- never refreshed, and the button sat disabled with nothing
// saying why.
$("plnew").oninput = () => refreshRoutePolicy();
$("rmnew").oninput = () => refreshRoutePolicy();
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

    // The motion rules, as a rule rather than as a habit.
    //
    // Every line here is a thing that reads as sloppy on an appliance an
    // operator stares at all day: a transition that animates whatever happens
    // to change, an ease-in that delays the moment being watched, something
    // that pops out of nothing, a UI animation long enough to wait for. They
    // are cheap to reintroduce by copying a snippet from elsewhere, which is
    // exactly why they are pinned.
    #[test]
    fn the_console_keeps_its_motion_rules() {
        let html = page();
        let css = html
            .split_once("<style>")
            .and_then(|(_, rest)| rest.split_once("</style>"))
            .map(|(css, _)| css.to_string())
            .expect("the page has a stylesheet");

        assert!(
            !css.contains("transition: all"),
            "`transition: all` animates whatever happens to change — name the properties"
        );
        assert!(
            !css.contains("scale(0)"),
            "nothing appears from nothing: enter from scale(.95)-ish with opacity 0"
        );
        // `ease-in` alone, not `ease-in-out`: the first delays the moment the
        // user is looking at, the second is the sanctioned curve for movement.
        assert!(
            !css.replace("ease-in-out", "").contains("ease-in"),
            "`ease-in` starts slow exactly where the eye is — use ease-out"
        );
        assert!(
            css.contains("prefers-reduced-motion"),
            "reduced motion is not optional"
        );
        // Gentler, not gone: a blanket kill removes the fades that explain a
        // surface arriving along with the movement that was the problem.
        assert!(
            !css.contains("transition: none !important"),
            "reduced motion means fewer and gentler animations, not none at all"
        );
        // Every duration a person waits for, in one place, all under the mark.
        for (token, ms) in [("--dur-fast", 130u32), ("--dur-base", 200)] {
            assert!(
                css.contains(&format!("{token}: {ms}ms")),
                "{token} is no longer {ms}ms — UI motion stays under 300ms"
            );
        }
        // Curves are taken from the reference set, not approximated.
        for curve in [
            "--ease-out: cubic-bezier(0.23, 1, 0.32, 1)",
            "--ease-in-out: cubic-bezier(0.77, 0, 0.175, 1)",
        ] {
            assert!(
                css.contains(curve),
                "the motion tokens no longer hold {curve}"
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
            "metrics enable",
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
        assert!(html.contains("push(`set ${path} ${f[0]} ${v}`)"));
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
        assert!(page().contains(r#"push(`delete ${path} ${CLEARS[f[0]] || f[0]}`)"#));
    }

    /// …with the setting the appliance actually has. A rule's schedule is three
    /// leaves of one thing and the CLI has no `delete … schedule days`, so
    /// emptying the days has to remove the window — the console used to write
    /// the command that does not exist, and its refusal took the whole batch.
    #[test]
    fn a_setting_that_cannot_be_removed_alone_removes_what_it_belongs_to() {
        let html = page();
        for leaf in ["schedule days", "schedule start", "schedule end"] {
            assert!(
                html.contains(&format!("\"{leaf}\": \"schedule\"")),
                "{leaf} still stages a delete of a path the appliance does not have"
            );
        }
    }

    /// A value the console offers has to be one the appliance takes.
    ///
    /// The chips beside a community list were written from what the RFCs
    /// define, which is a longer list than what this box validates: two of the
    /// five were words it refuses at commit. An offer the appliance rejects is
    /// worse than no offer — it is the console recommending the mistake.
    #[test]
    fn every_community_offered_is_one_the_appliance_takes() {
        let html = page();
        let (_, rest) = html
            .split_once("const WELL_KNOWN_COMMUNITIES = [")
            .expect("the community chips are gone");
        let (list, _) = rest.split_once(']').expect("unterminated list");
        let offered: Vec<&str> = list
            .split(',')
            .map(|s| s.trim().trim_matches('"'))
            .filter(|s| !s.is_empty())
            .collect();
        assert!(!offered.is_empty(), "no communities offered at all");
        for one in offered {
            crate::config::validate_community(one).unwrap_or_else(|e| {
                panic!("the console offers {one:?}, which this box refuses: {e}")
            });
        }
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
            html.contains("if (committed && !refused)"),
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
            "MutationObserver",
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
            html.contains("border-radius: 50%;\n    background: var(--text-faint); flex: none;"),
            "the mark on a configured page took a signal colour again"
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
        // The platform face leads and the named faces remain as fallbacks —
        // see the module header. Both are asserted so neither half of that
        // sentence can silently stop being true.
        assert!(
            html.contains("--font-sans: system-ui"),
            "the platform face no longer leads the stack"
        );
        assert!(
            html.contains("\"Space Grotesk\""),
            "the design system's face fell out of the stack entirely"
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
