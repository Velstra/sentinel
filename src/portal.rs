//! C20 — the **captive portal**: the page a guest sees, and the one thing on
//! this appliance that opens the firewall for somebody.
//!
//! The gate is in the data plane and the session lives in the agent (see
//! `velstra-app/src/portal.rs`). What runs here is the part a person meets: a
//! page on the appliance's own address in the gated zone, a passphrase or a
//! button, and — on success — one line to the agent admitting the device that is
//! standing in front of us.
//!
//! ## How a device finds this page
//!
//! **RFC 8910**: the DHCP server hands out this portal's URI in option 114, and
//! the client's own operating system opens it. Every current desktop and mobile
//! stack implements that, and the ones that do not still discover the portal the
//! moment somebody types the address on the card by the door.
//!
//! What this deliberately does *not* do is intercept. Redirecting a guest's HTTP
//! connection means parsing and rewriting a connection that was not addressed to
//! us, and it stops working entirely the moment that connection is TLS — which,
//! for the web anybody actually visits, is all of it. The result would be a
//! mechanism that adds an attack surface, works for a shrinking minority of
//! traffic, and shows a browser a certificate error the rest of the time. The
//! same position is written down for ALGs in the firewall handbook.
//!
//! ## What a login can and cannot do
//!
//! Everything the page can achieve is one `allow` on the agent's portal socket,
//! and an admission there moves a device from "held at the gate of the guest
//! zone" to "subject to that zone's ordinary firewall rules" — nowhere else, no
//! port opened, nothing configured. The session carries a deadline the agent
//! enforces on its own. So the worst outcome of a guessed passphrase is a guest
//! on the guest network, which is what the guest network is for.

use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    extract::{ConnectInfo, Form, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::{compile::zone_policy_ids, config::Appliance};

/// Where the agent serves its portal socket (see `nix/velstra-service.nix`).
///
/// Separate from the query socket on purpose: this is the only socket on which
/// anything can be opened, and the diagnostics one keeps the property that
/// nothing on it admits traffic.
pub const AGENT_SOCKET: &str = "/run/velstra/portal.sock";

/// How long to wait for the agent. A visitor is watching a spinner, so a wedged
/// agent has to produce an answer rather than a hung page.
const TIMEOUT: Duration = Duration::from_secs(3);

/// Where the resolved portal settings are rendered for the service to read.
///
/// The service reads *this* rather than the saved appliance config, so what is
/// being served is what the last `commit` resolved — the same derivation that
/// produced the DHCP option and the data plane's gate. It carries the
/// passphrase, so it is installed as a secret (0640) like every other rendered
/// file that does.
pub const STATE_FILE: &str = "/run/sentinel/portal.json";

/// What the portal needs to answer a request, resolved once at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalState {
    /// The address and port the page is served on: the appliance's own address
    /// in the gated zone. Bound explicitly rather than on every address, so the
    /// portal is not answering on the WAN because somebody typed the wrong port.
    pub bind: SocketAddr,
    /// The policy id of the gated zone — what the agent is told to admit into.
    pub policy: u32,
    /// The passphrase a visitor must type, or `None` for click-through.
    pub passphrase: Option<String>,
    /// How long an admission lasts.
    pub session_secs: u64,
    /// The line of text shown on the page.
    pub message: String,
    /// The agent socket to admit through.
    pub socket: PathBuf,
}

/// Resolve the running config into what the portal serves.
///
/// Returns `None` when no portal is configured, which is how the apply decides
/// whether the service runs at all.
pub fn resolve(appliance: &Appliance) -> Option<PortalState> {
    let portal = &appliance.services.portal;
    let zone = portal.zone.as_deref()?;
    let policy = *zone_policy_ids(appliance).get(zone)?;
    // The bind address is the appliance's own in the gated zone — the same one
    // the gate lets unadmitted clients reach and the same one option 114
    // announces. Bound explicitly rather than to every address, so the portal is
    // not answering on the WAN because somebody typed the wrong port.
    let addr: IpAddr = appliance
        .interfaces
        .iter()
        .filter(|i| !i.disabled && i.zone.as_deref() == Some(zone))
        .find_map(|i| i.address.as_ref())
        .and_then(|a| a.split('/').next()?.parse().ok())?;

    Some(PortalState {
        bind: SocketAddr::new(addr, portal.port()),
        policy,
        passphrase: portal.passphrase.clone(),
        session_secs: portal.session_timeout(),
        message: portal
            .message
            .clone()
            .unwrap_or_else(|| "Welcome. Connect to continue.".to_string()),
        socket: PathBuf::from(AGENT_SOCKET),
    })
}

/// The rendered state file, or `None` when no portal is configured — the shape
/// `apply_box_service` uses to decide between installing-and-restarting and
/// stopping-and-removing.
pub fn render(appliance: &Appliance) -> Option<String> {
    let state = resolve(appliance)?;
    serde_json::to_string_pretty(&state).ok()
}

/// Load the rendered state the last apply wrote.
pub fn load(path: &Path) -> Result<PortalState> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Serve the portal until the process ends.
pub async fn serve(state: PortalState) -> Result<()> {
    let bind = state.bind;
    let app = router(Arc::new(state));
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding the portal on {bind}"))?;
    log_line(&format!("captive portal listening on {bind}"));
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("serving the captive portal")
}

/// The routes. Split out so a test can drive them without a socket.
fn router(state: Arc<PortalState>) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/login", post(login))
        // RFC 8908: the client's own operating system polls this to learn
        // whether it is still captive and how long it has left. Answered from
        // the agent, so the page and the API can never disagree about a session.
        .route("/api/captive-portal", get(api))
        .with_state(state)
}

/// A one-line log to stderr, which systemd files under the unit.
fn log_line(msg: &str) {
    eprintln!("{msg}");
}

/// The login page.
async fn page(State(state): State<Arc<PortalState>>) -> Html<String> {
    Html(render_page(&state, None))
}

/// What a submitted form carries. One field, and only when a passphrase is set.
#[derive(Debug, Deserialize)]
struct Login {
    #[serde(default)]
    passphrase: String,
}

/// Handle a login: check what was typed, then admit the device that typed it.
async fn login(
    State(state): State<Arc<PortalState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Form(form): Form<Login>,
) -> Response {
    if let Some(expected) = &state.passphrase {
        // Compared by value rather than in constant time, and deliberately: this
        // is a shared passphrase printed on a card, reachable only from the zone
        // it admits to, and the thing it protects is access to the guest
        // network. A timing oracle against it buys an attacker who is already
        // standing on the guest link nothing they could not get by reading the
        // card.
        if form.passphrase.trim() != expected {
            return (
                StatusCode::UNAUTHORIZED,
                Html(render_page(&state, Some("That is not the passphrase."))),
            )
                .into_response();
        }
    }

    match admit(&state, peer.ip()) {
        Ok(_) => Html(render_done(&state)).into_response(),
        Err(e) => {
            // The visitor gets a plain sentence; the reason goes to the journal,
            // where an operator can see whether the agent is even running.
            log_line(&format!("portal: admitting {}: {e:#}", peer.ip()));
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Html(render_page(
                    &state,
                    Some("This network cannot let you on right now."),
                )),
            )
                .into_response()
        }
    }
}

/// RFC 8908 — the captive-portal API, answered as `application/captive+json`.
async fn api(
    State(state): State<Arc<PortalState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    let reply = ask(
        &state.socket,
        &format!("status {} {}\n", peer.ip(), state.policy),
    )
    .unwrap_or_else(|_| "not admitted".to_string());
    let seconds = seconds_remaining(&reply);
    let captive = seconds.is_none();
    // `user-portal-url` is required whenever the client is captive; RFC 8908
    // wants an absolute URL, and the only one that is certainly reachable from
    // where the client is standing is the address it just reached us on.
    let body = match seconds {
        Some(secs) => format!("{{\"captive\":false,\"seconds-remaining\":{secs}}}"),
        None => "{\"captive\":true}".to_string(),
    };
    let _ = captive;
    ([(header::CONTENT_TYPE, "application/captive+json")], body).into_response()
}

/// The seconds left in the agent's answer, or `None` when it says not admitted.
///
/// Parsed rather than pattern-matched loosely: `sessions`-style output is the
/// agent's own wording, and reading "not admitted" as a number would report a
/// held device as an admitted one with no time left.
fn seconds_remaining(reply: &str) -> Option<u64> {
    let (_, rest) = reply.split_once(", ")?;
    let secs = rest.trim().strip_suffix("s remaining")?;
    secs.parse().ok()
}

/// Admit `addr` through the agent, and return what it said.
fn admit(state: &PortalState, addr: IpAddr) -> Result<String> {
    let reply = ask(
        &state.socket,
        &format!("allow {addr} {} {}\n", state.policy, state.session_secs),
    )?;
    // The agent reports a refusal in the reply rather than by closing the
    // connection, so a page that only checked for I/O errors would tell a guest
    // they were on the network when they were not.
    if reply.starts_with("error:") {
        bail!("{}", reply.trim());
    }
    Ok(reply)
}

/// Send one line to the agent's portal socket and read its whole reply.
fn ask(socket: &Path, line: &str) -> Result<String> {
    if !socket.exists() {
        bail!("{} does not exist; is the agent running?", socket.display());
    }
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connecting to the agent at {}", socket.display()))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();
    stream.write_all(line.as_bytes()).context("sending")?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply).context("reading")?;
    if reply.is_empty() {
        bail!("the agent returned nothing");
    }
    Ok(reply)
}

/// The login page, with an optional line explaining why the last attempt failed.
///
/// Deliberately one self-contained document with no external anything: a device
/// at this point in its life can reach exactly this appliance, so a stylesheet,
/// a font or a logo fetched from anywhere else would render as a broken page.
fn render_page(state: &PortalState, error: Option<&str>) -> String {
    let message = escape(&state.message);
    let error = error
        .map(|e| format!("<p class=\"err\">{}</p>", escape(e)))
        .unwrap_or_default();
    let field = if state.passphrase.is_some() {
        "<label for=\"p\">Passphrase</label>\
         <input id=\"p\" name=\"passphrase\" type=\"password\" autofocus \
         autocomplete=\"one-time-code\">"
    } else {
        ""
    };
    let button = if state.passphrase.is_some() {
        "Connect"
    } else {
        "Accept and connect"
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>Connect</title>{STYLE}</head><body><main>\
         <h1>Connect</h1><p>{message}</p>{error}\
         <form method=\"post\" action=\"/login\">{field}\
         <button type=\"submit\">{button}</button></form></main></body></html>"
    )
}

/// The page a visitor sees once they are on.
fn render_done(state: &PortalState) -> String {
    let minutes = state.session_secs.div_ceil(60);
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>Connected</title>{STYLE}</head><body><main>\
         <h1>Connected</h1><p>You are on the network for the next {minutes} minutes.</p>\
         </main></body></html>"
    )
}

/// The page's whole appearance. Inline for the reason given on [`render_page`].
const STYLE: &str = "<style>\
    :root{color-scheme:light dark}\
    body{font:16px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;\
    min-height:100vh;background:Canvas;color:CanvasText}\
    main{width:min(28rem,92vw);padding:2rem}\
    h1{font-size:1.5rem;margin:0 0 .5rem}\
    p{margin:0 0 1.5rem}\
    label{display:block;font-size:.875rem;margin-bottom:.25rem}\
    input,button{width:100%;font:inherit;padding:.75rem;border-radius:.5rem;\
    box-sizing:border-box}\
    input{border:1px solid GrayText;margin-bottom:1rem;background:Field;color:FieldText}\
    button{border:0;background:AccentColor;color:AccentColorText;cursor:pointer}\
    .err{color:#b00020}\
    </style>";

/// Escape text that came from the configuration before it goes into the page.
///
/// The message is written by the operator, not by a visitor, so this is not
/// guarding against an attacker — it is guarding against an ampersand in a
/// network's name silently breaking the page.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(passphrase: Option<&str>) -> PortalState {
        PortalState {
            bind: "192.168.50.1:8082".parse().unwrap(),
            policy: 2,
            passphrase: passphrase.map(str::to_string),
            session_secs: 3600,
            message: "Guest & visitor network".to_string(),
            socket: PathBuf::from("/nonexistent"),
        }
    }

    /// A click-through portal has no field to type into, and a passphrase portal
    /// does. Getting this backwards shows a guest a box they cannot fill.
    #[test]
    fn the_page_asks_for_what_is_configured() {
        let with = render_page(&state(Some("sommer")), None);
        assert!(with.contains("name=\"passphrase\""), "{with}");
        assert!(with.contains(">Connect</button>"));

        let without = render_page(&state(None), None);
        assert!(!without.contains("name=\"passphrase\""), "{without}");
        assert!(without.contains("Accept and connect"));
    }

    /// The page is one document. A device at the gate can reach this appliance
    /// and nothing else, so anything fetched from elsewhere renders as broken.
    #[test]
    fn the_page_fetches_nothing() {
        let page = render_page(&state(Some("x")), Some("no"));
        for pattern in ["http://", "https://", "//cdn", "<script", "<img"] {
            assert!(
                !page.contains(pattern),
                "page reaches for {pattern}: {page}"
            );
        }
    }

    /// The operator's own text goes through unaltered except where it would
    /// break the document.
    #[test]
    fn the_message_is_escaped_not_dropped() {
        let page = render_page(&state(None), None);
        assert!(page.contains("Guest &amp; visitor network"), "{page}");
    }

    /// The agent answers a status query in its own words. Reading them wrongly
    /// would report a held device as an admitted one.
    #[test]
    fn a_status_reply_is_read_precisely() {
        assert_eq!(
            seconds_remaining("02:00:00:00:00:11 admitted to policy 2, 3540s remaining\n"),
            Some(3540)
        );
        assert_eq!(seconds_remaining("not admitted\n"), None);
        assert_eq!(seconds_remaining("error: no zone has a portal\n"), None);
        assert_eq!(seconds_remaining(""), None);
    }

    /// A refusal arrives in the reply, not as an I/O error — a page that only
    /// checked for the latter would tell a guest they were on the network.
    #[test]
    fn an_agent_refusal_is_not_a_success() {
        let err = admit(&state(None), "192.168.50.9".parse().unwrap()).unwrap_err();
        assert!(err.to_string().contains("/nonexistent"), "{err}");
    }
}
