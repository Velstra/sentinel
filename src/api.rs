//! The REST management API (roadmap C12).
//!
//! pfSense/OPNsense expose a Web UI + API; a core Sentinel principle is **one
//! config model** — the CLI, this API and (later) the Web UI all drive the same
//! versioned config tree, so there is no UI-vs-CLI drift. This module is the API
//! slice of that: an HTTP server over the *same* [`Appliance`] document the
//! `configure` shell edits and the same operational `show` data.
//!
//! Everything here is a thin transport over existing logic — it invents no new
//! config surface:
//!
//! - `PUT /api/v1/config` parses the body with [`Appliance::from_json`] (the same
//!   parse+validate the CLI runs), applies it with [`repl::apply_live`] — the
//!   exact live-apply path a CLI `commit` takes — and persists it with
//!   [`session::persist_appliance`], the same save path the CLI `save` uses.
//! - `GET /api/v1/config` returns the running [`Appliance`] as JSON.
//! - `GET /api/v1/status` and `GET /api/v1/show/*` surface the operational state
//!   the `show` commands report.
//! - `GET /` serves the **web console** ([`crate::webui`]) — a read-only view over
//!   those same endpoints, so it cannot report anything the CLI would not.
//!
//! Auth is a bearer token (0600 file or `$SENTINEL_API_TOKEN`), required on every
//! endpoint except `/api/v1/health`. The server binds localhost by default; widen it
//! with `--listen 0.0.0.0:<port>`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path as UrlPath, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use serde_json::{Value, json};

use crate::capture;
use crate::config::Appliance;
use crate::repl::{self, Apply};
use crate::session;
use crate::system;

/// The default listen address — localhost, so the API is not exposed off-box
/// unless the operator explicitly widens it with `--listen`.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
/// The default bearer-token file (0600, persistent, never in the image).
pub const DEFAULT_TOKEN_PATH: &str = "/var/lib/sentinel/api-token";

/// Shared handler state: the bearer token, the running-config path, and how a
/// `PUT` applies the config live (the same [`Apply`] a CLI `commit` uses).
pub struct ApiState {
    /// The bearer token every request (except `/api/v1/health`) must present.
    pub token: String,
    /// The running/boot config a `GET` reads and a `PUT` writes.
    pub config_path: PathBuf,
    /// Whether/where a `PUT` applies the config to the running system.
    pub apply: Apply,
    /// Directory holding one token file per account with management access.
    ///
    /// Per-account tokens rather than per-account passwords: the appliance
    /// already stores a crypt(3) hash for shell login, and verifying one here
    /// would mean carrying a password-hashing implementation into the request
    /// path to gain nothing — a token is what an API client sends anyway, and a
    /// token can be withdrawn by deleting a file.
    pub tokens_dir: PathBuf,
}

/// Where per-account API tokens live when the machine token's directory cannot
/// be determined. One file per account, 0600, beside the machine token.
pub const DEFAULT_TOKENS_DIR: &str = "/var/lib/sentinel/api-tokens";

/// Who is asking, and what they may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The account name, or `None` for the machine token.
    pub user: Option<String>,
    /// What this caller may do.
    pub permission: crate::config::Permission,
}

/// Serve the REST API until the process is stopped. Loads (or generates) the
/// bearer token, then binds `listen` and serves the router.
pub async fn serve(listen: &str, config: &Path, apply: Apply, token_file: &Path) -> Result<()> {
    let token = load_or_create_token(token_file)?;
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("parsing --listen {listen:?} (want host:port)"))?;
    let state = Arc::new(ApiState {
        token,
        config_path: config.to_path_buf(),
        apply,
        // Beside the machine token, wherever that was put. Deriving it rather
        // than hard-coding the appliance path means an off-box run — the one an
        // operator uses to look at the console — mints its accounts somewhere it
        // can actually write.
        tokens_dir: token_file
            .parent()
            .map(|d| d.join("api-tokens"))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_TOKENS_DIR)),
    });
    // Mint a token for every account that has been given a group, and withdraw
    // the ones whose account or group is gone. Done at startup rather than at
    // apply so a token exists the first time the API runs, and re-done on every
    // `PUT` (which restarts nothing) by the same call below.
    if let Err(e) = sync_user_tokens(&state) {
        eprintln!("warning: could not reconcile per-account API tokens: {e:#}");
    }
    let app = router(state);

    match resolve_web_tls(config, token_file, &addr)? {
        // HTTPS (H3, the default): the console/API terminate TLS so passwords,
        // TOTP codes and bearer tokens never cross the wire in the clear.
        Some((cert, key)) => {
            install_crypto_provider();
            match system::cert_pubkey_pin(&cert) {
                Ok(pin) => eprintln!(
                    "sentinel api listening on https://{addr} (bearer-token auth; token at {}; \
                     TLS pin sha256//{pin} — pin this on a config-sync peer)",
                    token_file.display()
                ),
                Err(_) => eprintln!(
                    "sentinel api listening on https://{addr} (bearer-token auth; token at {})",
                    token_file.display()
                ),
            }
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                .await
                .with_context(|| {
                    format!(
                        "loading the management TLS certificate ({}) + key ({})",
                        cert.display(),
                        key.display()
                    )
                })?;
            // `into_make_service_with_connect_info::<SocketAddr>` so the login
            // handler can see the peer address and apply a per-IP lockout —
            // without it every request would look like it came from nowhere.
            axum_server::bind_rustls(addr, tls)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .context("serving the management API over HTTPS")?;
        }
        // Opt-in plaintext (`[services.web] tls = false`): loopback/dev, or behind
        // an external TLS terminator. Say plainly that it is unencrypted.
        None => {
            eprintln!(
                "sentinel api listening on http://{addr} (bearer-token auth; token at {}) — \
                 PLAINTEXT: tls is disabled, so use this only on a trusted or loopback network",
                token_file.display()
            );
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding {addr}"))?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .context("serving the REST API")?;
        }
    }
    Ok(())
}

/// Decide how the management server terminates TLS (H3). Returns the PEM
/// certificate and key paths to serve HTTPS with, or `None` when `[services.web]
/// tls = false` deliberately asked for plaintext. With no operator-supplied
/// certificate, a self-signed one is minted once and persisted beside the API
/// token — on the appliance that is the A/B-stable `/var/lib/sentinel`, so the
/// certificate (and its pin) survives reboots and image updates.
fn resolve_web_tls(
    config: &Path,
    token_file: &Path,
    addr: &SocketAddr,
) -> Result<Option<(PathBuf, PathBuf)>> {
    // Lenient, like the boot path: a management server must still come up on a
    // config a newer build wrote. A load failure falls back to the safe default
    // (TLS on, self-signed), never to plaintext.
    let web = Appliance::load_lenient(config)
        .map(|a| a.services.web)
        .unwrap_or_default();
    if !web.tls {
        return Ok(None);
    }
    if let (Some(cert), Some(key)) = (&web.tls_cert, &web.tls_key) {
        return Ok(Some((PathBuf::from(cert), PathBuf::from(key))));
    }
    let dir = token_file
        .parent()
        .map(|p| p.join("web-tls"))
        .unwrap_or_else(|| PathBuf::from("/var/lib/sentinel/web-tls"));
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let cn = system::current_hostname();
    let mut sans = vec!["127.0.0.1".to_string()];
    if !addr.ip().is_unspecified() {
        sans.push(addr.ip().to_string());
    }
    system::ensure_self_signed_cert(&cert, &key, &cn, &sans)?;
    Ok(Some((cert, key)))
}

/// Install the ring crypto provider as the process default. rustls 0.23 requires
/// a default provider before a server config can be built; ring is the one
/// already in the dependency tree, and a repeat install is a harmless no-op.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build the API router. `/api/v1/health` is unauthenticated; everything else sits
/// behind the bearer-token middleware.
pub fn router(state: Arc<ApiState>) -> Router {
    let protected = Router::new()
        .route("/api/v1/config", get(get_config).put(put_config))
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/show/*path", get(get_show))
        .route("/api/v1/rule-hits", get(get_rule_hits))
        .route("/api/v1/trace", get(get_trace))
        .route("/api/v1/metrics", get(get_metrics_list))
        .route("/api/v1/metrics/:resolution/:series", get(get_metrics))
        // The Prometheus scrape target, at the conventional `/metrics`. Same
        // data as the JSON endpoints above, in text exposition format, behind the
        // same bearer auth (it is part of this protected sub-router).
        .route("/metrics", get(get_metrics_prometheus))
        .route("/api/v1/configure", post(post_configure))
        .route("/api/v1/clear/*path", post(post_clear))
        .route("/api/v1/capture", post(post_capture))
        // What the appliance can tell you about a value you are typing. The
        // console never reaches outside itself; it asks here, and this asks the
        // world — which is why a page served on an isolated network still works.
        .route("/api/v1/lookup/:kind/:value", get(get_lookup))
        // …and what the appliance can tell you about itself. A timezone or a
        // keymap is a closed set this box knows and this binary deliberately
        // does not, so the picker for one is filled from here.
        .route("/api/v1/choices/:kind", get(get_choices))
        .route("/api/v1/stack", get(get_stack))
        .route("/api/v1/stack/:member/show/*path", get(get_stack_show))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token));
    Router::new()
        .route("/api/v1/health", get(health))
        // The surface as a document. Open like `health`: a client has to read
        // it before it can know how to sign in, and it names no secret.
        .route("/api/v1/openapi.json", get(get_openapi))
        // Signing in cannot require being signed in. The account's password is
        // checked here and the account's own token is handed back — the same
        // token an operator could read off the box, so nothing new is granted
        // by knowing the password, only a way to ask for it.
        .route("/api/v1/login", post(post_login))
        // The console itself is markup with no data in it, and a sign-in page
        // that needs a token to reach is not a sign-in page. Everything it then
        // fetches goes through the middleware above like any other client.
        .route("/", get(console))
        .route("/ui", get(console))
        .route("/favicon.ico", get(favicon))
        .merge(protected)
        .with_state(state)
}

/// `GET /favicon.ico` — the tab icon (see [`crate::webui::FAVICON_PNG`]).
async fn favicon() -> impl axum::response::IntoResponse {
    (
        [
            (axum::http::header::CONTENT_TYPE, "image/png"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        crate::webui::FAVICON_PNG,
    )
}

/// `GET /` — the web console (roadmap C12).
async fn console() -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        crate::webui::page(),
    )
        .into_response()
}

// ---- middleware ----------------------------------------------------------

/// Reject any request whose `Authorization: Bearer <token>` does not match the
/// configured token. The comparison is constant-time so a wrong token leaks no
/// timing signal about how many bytes were right.
async fn require_token(
    State(state): State<Arc<ApiState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let Some(token) = provided else {
        return unauthorised();
    };
    let Some(caller) = resolve_caller(&state, token) else {
        return unauthorised();
    };
    // A read-only caller may read anything and change nothing. The split is by
    // **method**, not by path: every endpoint that changes something is a POST
    // or a PUT, and enumerating paths instead would leave the next endpoint
    // added silently writable by everyone.
    if !caller.permission.may_write() && req.method() != axum::http::Method::GET {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": format!(
                    "{} is read-only",
                    caller.user.as_deref().unwrap_or("this token"),
                ),
            })),
        )
            .into_response();
    }
    // Handlers get to know who is asking. A console that has been reloaded
    // holds a token and nothing else — it has to be able to ask the appliance
    // whose it is, or it cannot say who is signed in or what they may do.
    req.extensions_mut().insert(caller);
    next.run(req).await
}

/// The 401 every failed authentication gets, worded the same way whether the
/// token was absent, malformed or simply wrong — a different message per case
/// tells an attacker which half they got right.
fn unauthorised() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "missing or invalid bearer token" })),
    )
        .into_response()
}

/// Resolve a presented token to who is asking and what they may do.
///
/// The **machine token** is full access and has no account behind it: it is what
/// a peer firewall presents when config-sync pushes a commit, and what an
/// operator uses before any account exists. Everything else is an account token,
/// and its permission comes from the account's group — so withdrawing access is
/// either deleting the token file or changing the group, both of which are
/// visible where somebody would look.
pub fn resolve_caller(state: &ApiState, presented: &str) -> Option<Caller> {
    use crate::config::Permission;
    // An empty bearer never authenticates anything. `ct_eq(b"", b"")` is `true`,
    // so an empty presented token would match an empty configured token or an
    // empty token file — turning `Authorization: Bearer ` into full or account
    // access. Refuse it before any comparison.
    if presented.is_empty() {
        return None;
    }
    if ct_eq(presented.as_bytes(), state.token.as_bytes()) {
        return Some(Caller {
            user: None,
            permission: Permission::ReadWrite,
        });
    }
    let appliance = Appliance::load(&state.config_path).ok()?;
    let entries = std::fs::read_dir(&state.tokens_dir).ok()?;
    for entry in entries.flatten() {
        let Ok(stored) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let stored = stored.trim();
        // An empty token file grants nothing: a half-written or truncated token
        // must never authenticate an (also-empty) presented bearer.
        if stored.is_empty() {
            continue;
        }
        if !ct_eq(presented.as_bytes(), stored.as_bytes()) {
            continue;
        }
        let user = entry.file_name().to_string_lossy().into_owned();
        // A token file whose account or group has since gone grants nothing:
        // the config is the authority, and the file is only the secret.
        let login = appliance
            .system
            .logins
            .iter()
            .find(|l| l.username == user)?;
        let group = login.group.as_deref()?;
        let permission = appliance
            .system
            .groups
            .iter()
            .find(|g| g.name == group)?
            .permission;
        return Some(Caller {
            user: Some(user),
            permission,
        });
    }
    None
}

/// Mint a token for every account with a group, and remove the files of accounts
/// that no longer have one.
///
/// A token is generated once and then left alone: rotating it on every apply
/// would log every client out whenever anything at all was committed.
pub fn sync_user_tokens(state: &ApiState) -> Result<()> {
    let appliance = Appliance::load(&state.config_path)?;
    let wanted: Vec<&str> = appliance
        .system
        .logins
        .iter()
        .filter(|l| l.group.is_some())
        .map(|l| l.username.as_str())
        .collect();
    if wanted.is_empty() && !state.tokens_dir.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(&state.tokens_dir)
        .with_context(|| format!("creating {}", state.tokens_dir.display()))?;
    for user in &wanted {
        let path = state.tokens_dir.join(user);
        if !path.exists() {
            load_or_create_token(&path)?;
        }
    }
    // Withdraw what is no longer granted.
    for entry in std::fs::read_dir(&state.tokens_dir)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !wanted.iter().any(|u| *u == name) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}

// ---- handlers ------------------------------------------------------------

/// `GET /api/v1/rule-hits` — what each accept rule is currently carrying.
///
/// Attribution rather than a hardware counter, and the reply says so: a rule
/// that drops leaves no flow behind, so only accept rules can be counted this
/// way and a console that implied otherwise would invite somebody to delete a
/// drop rule that is doing its job.
async fn get_rule_hits(State(state): State<Arc<ApiState>>) -> Result<Json<Value>, ApiError> {
    let appliance = Appliance::load(&state.config_path)
        .map_err(|e| ApiError::internal(anyhow!("reading the configuration: {e}")))?;
    let cfg = crate::compile::compile(&appliance);
    let table = crate::velstra::query("flows --limit 0")
        .or_else(|_| crate::velstra::query("flows"))
        .unwrap_or_default();
    let flows = crate::compile::parse_flows(&table);
    let hits = crate::compile::attribute(&cfg, &flows);
    Ok(Json(json!({
        "counts_only": "accept",
        "flows": flows.len(),
        "answered": !table.trim().is_empty(),
        "rules": hits
            .into_iter()
            .map(|(name, h)| json!({ "name": name, "flows": h.flows, "packets": h.packets }))
            .collect::<Vec<_>>(),
    })))
}

/// `GET /api/v1/trace?in=lan0&proto=tcp&src=10.0.0.5&dst=10.9.0.10&port=22` —
/// where would this packet go, and which rule decides it.
///
/// A walk over the saved configuration, not a capture: nothing is sent and
/// nothing on the box is touched, which is why it is a GET. The same answer
/// `sentinel trace` prints, as JSON — see [`crate::trace`] for what it can and
/// cannot know.
async fn get_trace(
    State(state): State<Arc<ApiState>>,
    axum::extract::Query(query): axum::extract::Query<crate::trace::Query>,
) -> Result<Json<crate::trace::Trace>, ApiError> {
    let appliance = Appliance::load(&state.config_path)
        .map_err(|e| ApiError::internal(anyhow!("reading the configuration: {e}")))?;
    let answer = crate::trace::trace(&appliance, &query).map_err(ApiError::bad_request)?;
    Ok(Json(answer))
}

/// Per-rule hit counters as `(name, flows, packets)`, the same attribution the
/// JSON `/api/v1/rule-hits` reports — factored out so the Prometheus adapter and
/// the JSON endpoint can never disagree about the numbers.
fn rule_hit_counts(config_path: &Path) -> Vec<(String, u64, u64)> {
    let Ok(appliance) = Appliance::load(config_path) else {
        return Vec::new();
    };
    let cfg = crate::compile::compile(&appliance);
    let table = crate::velstra::query("flows --limit 0")
        .or_else(|_| crate::velstra::query("flows"))
        .unwrap_or_default();
    let flows = crate::compile::parse_flows(&table);
    crate::compile::attribute(&cfg, &flows)
        .into_iter()
        .map(|(name, h)| (name, h.flows, h.packets))
        .collect()
}

/// `GET /metrics` — the live counters in Prometheus text exposition format.
///
/// Behind the same bearer-token auth as every other endpoint (it sits in the
/// protected router), so a scraper presents the account/machine token like any
/// other client. This is a **format adapter**: it exposes the exact numbers the
/// JSON endpoints do — per-interface byte counters, per-rule hit counters and the
/// session gauge — as raw running totals, letting the scraper do its own rate
/// maths. See [`crate::metrics::prometheus_exposition`].
async fn get_metrics_prometheus(State(state): State<Arc<ApiState>>) -> Response {
    let ifaces = crate::metrics::interface_counters().unwrap_or_default();
    let hits = rule_hit_counts(&state.config_path);
    let sessions = crate::metrics::session_count();
    let body = crate::metrics::prometheus_exposition(&ifaces, &hits, sessions);
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/// `GET /api/v1/metrics` — which series are being kept.
async fn get_metrics_list() -> Result<Json<Value>, ApiError> {
    let root = crate::metrics::dir();
    let root = root.as_path();
    Ok(Json(json!({
        "series": crate::metrics::series(root),
        "resolutions": crate::metrics::RESOLUTIONS
            .iter()
            .map(|r| json!({ "name": r.name, "step": r.step, "keep": r.keep }))
            .collect::<Vec<_>>(),
    })))
}

/// `GET /api/v1/metrics/<resolution>/<series>` — the samples, already turned
/// into what a chart wants.
///
/// The rate is derived here rather than in the browser so both the console and
/// `show history` answer the same question the same way — and so a counter
/// reset is a gap in one place instead of two.
async fn get_metrics(
    axum::extract::Path((resolution, series)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let root = crate::metrics::dir();
    let root = root.as_path();
    let Some(res) = crate::metrics::resolution(&resolution) else {
        return Err(ApiError::bad_request(anyhow!(
            "no such resolution {resolution:?}"
        )));
    };
    let samples = crate::metrics::read(root, &series, res)
        .map_err(|e| ApiError::internal(anyhow!("reading the history: {e}")))?;
    // A gauge is a level and a counter is a total; deriving a rate from a level
    // would draw the change in the number of sessions, which nobody wants.
    let points: Vec<Value> = if series.starts_with("gauge.") {
        samples
            .iter()
            .map(|s| json!({ "at": s.at, "value": s.value }))
            .collect()
    } else {
        crate::metrics::rates(&samples, res.step * 3)
            .into_iter()
            .map(|(at, rate)| json!({ "at": at, "value": rate }))
            .collect()
    };
    Ok(Json(json!({
        "series": series,
        "resolution": res.name,
        "step": res.step,
        "points": points,
    })))
}

/// `POST /api/v1/login` — a username and a password for the account's token.
///
/// Until this existed the console asked for a bearer token, which meant that in
/// practice one shared secret was passed around: there was no way to sign in
/// *as* somebody, so accounts and permission groups existed on the box and
/// nowhere else. This is the missing half — the password is checked against the
/// account's stored hash, and what comes back is that account's own token, with
/// its group's permission.
///
/// **A shell account is not a management account.** An account with no group can
/// log in to the box and gets nothing here, and it is told exactly that: a
/// refusal an operator cannot act on is a support ticket.
///
/// Failures are slowed and counted two ways. **Per account** the delay grows but
/// there is no lockout — locking an administrator out of their own account is a
/// denial of service anyone can trigger by guessing their name. **Per source IP**
/// there IS a lockout: a single address grinding through passwords is stopped
/// cold after enough failures, and while locked its guesses are refused *before*
/// the expensive password hash runs — which is the point, since the hash is the
/// work an attacker was trying to make the box do. A locked address is one
/// address; the operator reaching the box from anywhere else is unaffected.
///
/// The peer address comes from `ConnectInfo`, which the server wires in via
/// `into_make_service_with_connect_info`. When it is absent (an in-process test,
/// or a transport with no peer address) the per-IP limiter is simply skipped and
/// the per-account throttle still applies.
async fn post_login(
    State(state): State<Arc<ApiState>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let peer_ip = connect_info.map(|ci| ci.0.ip());
    // A locked address is refused up front — cheaply, before the password hash
    // that a guesser is really trying to spend the box's CPU on.
    if let Some(ip) = peer_ip {
        if let Some(remaining) = ip_lockout_remaining(ip) {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                anyhow!(
                    "too many failed sign-ins from your address; locked for another {remaining}s"
                ),
            ));
        }
    }
    let username = body
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .trim()
        .to_string();
    let password = body
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let code = body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if username.is_empty() || password.is_empty() {
        return Err(ApiError::bad_request(anyhow!(
            "a username and a password are needed"
        )));
    }
    // Guessing costs time whether or not the account exists, so a wrong username
    // and a wrong password look the same from outside. The delay is AWAITED, not
    // slept on a thread: earlier it was a blocking sleep inside `spawn_blocking`,
    // so a couple of hundred concurrent guesses pinned every blocking thread (up
    // to 2 s each) and the API — and the console behind it — went dark.
    let attempts = note_attempt(&username);
    tokio::time::sleep(attempt_delay(attempts)).await;

    let state = state.clone();
    // Off the runtime: hashing is deliberately slow, and a login must not stall
    // the executor that is serving everybody else.
    let outcome = tokio::task::spawn_blocking(move || sign_in(&state, &username, &password, &code))
        .await
        .map_err(|e| ApiError::internal(anyhow!("login task: {e}")))?;
    match outcome {
        Ok(session) => {
            // A good sign-in clears the address: an operator who mistyped twice
            // and then got it right is not one attempt away from a lockout.
            if let Some(ip) = peer_ip {
                forget_ip(ip);
            }
            Ok(Json(session))
        }
        Err(refusal) => {
            if let Some(ip) = peer_ip {
                note_ip_failure(ip);
            }
            Err(refusal)
        }
    }
}

/// What consulting the configured servers concluded, when one of them answered.
///
/// A rejection carries which protocol's server said no, so the refusal can name
/// it — with three kinds of server configurable, "not accepted" alone sends an
/// operator diffing three configs to find the one that decided.
enum Consulted {
    Accepted,
    RejectedBy(&'static str),
}

/// Ask each configured server in turn, and say whether one of them accepted.
///
/// The order is RADIUS, then LDAP, then TACACS+ — fixed, like local-first, so
/// nobody has to reverse-engineer a precedence from a config file. The
/// distinction that matters: a server that **rejects** has answered, and no
/// other server is asked — a directory saying no is a decision. A server that
/// cannot be reached has not answered, so the next one is tried, and if none
/// answers at all that is an error rather than a refusal. Treating an
/// unreachable directory as a wrong password locks everybody out at exactly the
/// moment the network is already broken.
fn ask_the_directory(
    aaa: &crate::config::Aaa,
    hostname: &str,
    username: &str,
    password: &str,
) -> Result<Consulted, ApiError> {
    let mut last: Option<String> = None;
    for server in &aaa.radius {
        let timeout = std::time::Duration::from_secs(server.timeout.unwrap_or(3) as u64);
        match crate::aaa::radius_authenticate(
            &server.server,
            server.port.unwrap_or(1812),
            &server.secret,
            username,
            password,
            timeout,
            hostname,
        ) {
            Ok(true) => return Ok(Consulted::Accepted),
            Ok(false) => return Ok(Consulted::RejectedBy("RADIUS")),
            Err(e) => {
                eprintln!(
                    "warning: RADIUS server {} did not answer: {e}",
                    server.server
                );
                last = Some(e.to_string());
            }
        }
    }
    for d in &aaa.ldap {
        match crate::aaa::ldap_authenticate(
            &d.server,
            d.port,
            d.tls.as_deref().unwrap_or("ldaps"),
            &d.base_dn,
            d.user_attribute.as_deref().unwrap_or("uid"),
            username,
            password,
            d.timeout.unwrap_or(5),
        ) {
            Ok(crate::aaa::Directory::Accepted) => return Ok(Consulted::Accepted),
            Ok(crate::aaa::Directory::Rejected) => return Ok(Consulted::RejectedBy("LDAP")),
            Err(e) => {
                eprintln!("warning: LDAP directory {} did not answer: {e}", d.server);
                last = Some(e.to_string());
            }
        }
    }
    for t in &aaa.tacacs {
        let timeout = std::time::Duration::from_secs(t.timeout.unwrap_or(3) as u64);
        match crate::aaa::tacacs_authenticate(
            &t.server,
            t.port.unwrap_or(crate::aaa::TACACS_DEFAULT_PORT),
            &t.secret,
            username,
            password,
            timeout,
        ) {
            Ok(crate::aaa::Directory::Accepted) => return Ok(Consulted::Accepted),
            Ok(crate::aaa::Directory::Rejected) => return Ok(Consulted::RejectedBy("TACACS+")),
            Err(e) => {
                eprintln!("warning: TACACS+ server {} did not answer: {e}", t.server);
                last = Some(e.to_string());
            }
        }
    }
    Err(ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        anyhow!(
            "no authentication server answered ({}), and this account has no local password",
            last.unwrap_or_else(|| "none configured".into())
        ),
    ))
}

/// The whole of signing in, in one place so the refusals can be read together.
fn sign_in(
    state: &ApiState,
    username: &str,
    password: &str,
    code: &str,
) -> Result<Value, ApiError> {
    // The per-attempt slowdown and its counting happen in `post_login`, before
    // this runs — and crucially off the blocking pool, awaited asynchronously —
    // so a flood of guesses cannot pin blocking threads here.
    let appliance = Appliance::load(&state.config_path)
        .map_err(|e| ApiError::internal(anyhow!("reading the configuration: {e}")))?;
    let login = appliance
        .system
        .logins
        .iter()
        .find(|l| l.username == username);

    let refused = || {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            anyhow!("that username and password were not accepted"),
        )
    };

    // Local first, then the directory. Deliberately in that order and not
    // configurable: a box whose directory is unreachable must still be
    // enterable by the account written on it, and that is precisely the moment
    // the directory is likely to be unreachable.
    let local_ok = match login.and_then(|l| l.hashed_password.as_deref()) {
        Some(stored) => {
            // An unverifiable hash is not a wrong password, and saying "wrong
            // password" would send an operator hunting for a typo that is not
            // there.
            crate::passwd::verify(password, stored)
                .map_err(|e| ApiError::new(StatusCode::UNAUTHORIZED, anyhow!("{e}")))?
        }
        None => false,
    };
    if !local_ok {
        let aaa = &appliance.system.aaa;
        if !aaa.has_servers() {
            // No directory of ANY kind to fall back to, so the local answer is
            // the answer. Checking only RADIUS here refused every non-local login
            // on an LDAP-only box, because `ask_the_directory` (which tries LDAP
            // after RADIUS) was never reached.
            return Err(if login.is_some_and(|l| l.hashed_password.is_none()) {
                ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    anyhow!("that account has no password set"),
                )
            } else {
                refused()
            });
        }
        match ask_the_directory(aaa, &appliance.system.hostname, username, password)? {
            Consulted::Accepted => {}
            // The refusal names the protocol that decided — not the username,
            // not which part was wrong — so a caller probing accounts learns
            // nothing while an operator with three kinds of server configured
            // knows which one to look at.
            Consulted::RejectedBy(method) => {
                return Err(ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    anyhow!("that username and password were not accepted ({method} refused)"),
                ));
            }
        }
    }

    // A second factor is checked after the password and never instead of it, so
    // a wrong password and a wrong code are the same refusal from outside.
    if let Some(secret) = login.and_then(|l| l.totp.as_deref()) {
        if code.trim().is_empty() {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                anyhow!("{username} needs a one-time code as well as a password"),
            ));
        }
        let matched = crate::aaa::totp_matches(secret, code, crate::aaa::unix_now())
            .map_err(|e| ApiError::new(StatusCode::UNAUTHORIZED, anyhow!("{e}")))?;
        if !matched {
            return Err(refused());
        }
    }

    // What the account may do. A directory account with no local entry falls
    // back to the configured default group; without one it gets nothing, which
    // is what stops a configured server from handing management access to
    // everybody in the directory.
    let group =
        login
            .and_then(|l| l.group.as_deref())
            .or(appliance.system.aaa.default_group.as_deref());
    let Some(group) = group else {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            anyhow!(
                "{username} may log in to this appliance but has no management                  access — give the account a permission group"
            ),
        ));
    };
    let Some(permission) = appliance
        .system
        .groups
        .iter()
        .find(|g| g.name == group)
        .map(|g| g.permission)
    else {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            anyhow!("{username} is in group {group:?}, which does not exist"),
        ));
    };

    // The username becomes a filename (the account's per-account token file), so
    // it must be a strict account name and nothing that could climb out of the
    // tokens directory. A local login is already validated to this shape, but a
    // directory-authenticated account (RADIUS/LDAP/TACACS+ default-group) carries a name
    // straight from the request — `../../etc/cron.d/x` would otherwise be written
    // as a token file outside `tokens_dir`. Reject anything else before touching
    // the filesystem.
    if !valid_account_name(username) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            anyhow!("the account name is not a valid username"),
        ));
    }

    // The account's token, minted if this is the first time anybody asked.
    std::fs::create_dir_all(&state.tokens_dir)
        .map_err(|e| ApiError::internal(anyhow!("creating the token directory: {e}")))?;
    let token = load_or_create_token(&state.tokens_dir.join(username))
        .map_err(|e| ApiError::internal(anyhow!("minting the account's token: {e}")))?;
    forget_attempts(username);
    Ok(json!({
        "token": token,
        "user": username,
        "permission": match permission {
            crate::config::Permission::ReadOnly => "read-only",
            crate::config::Permission::ReadWrite => "read-write",
        },
    }))
}

/// Failed sign-ins per account, and when they started.
///
/// In memory on purpose: a restart clears it, and an operator who has locked
/// themselves out by fat-fingering a password should not have to find a file to
/// get back in.
fn attempts() -> &'static std::sync::Mutex<HashMap<String, (std::time::Instant, u32)>> {
    static ATTEMPTS: OnceLock<std::sync::Mutex<HashMap<String, (std::time::Instant, u32)>>> =
        OnceLock::new();
    ATTEMPTS.get_or_init(Default::default)
}

/// The most accounts whose failed attempts we track at once. A cap, not a tuning
/// knob: the map is a throttle, and an attacker spraying distinct usernames must
/// not be able to grow it without bound. When it is full and a new account
/// appears, quiet entries are forgotten first and, if that is not enough, the
/// least-recently-active entry is dropped.
const MAX_TRACKED_ACCOUNTS: usize = 4096;

/// How long the ten-minute forgiveness window lasts.
const ATTEMPT_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);

/// How long to slow a failed sign-in: 250 ms per attempt in the current window,
/// capped at 2 s. Awaited asynchronously by [`post_login`], never slept on a
/// thread, so it costs a guesser time without costing the server a worker.
fn attempt_delay(attempts: u32) -> std::time::Duration {
    std::time::Duration::from_millis(250 * attempts.min(8) as u64)
}

fn note_attempt(username: &str) -> u32 {
    let mut map = attempts().lock().unwrap();
    // Keep the map bounded before inserting a not-yet-seen account: forget the
    // quiet entries, then, if still at the cap, evict the least-recently-active
    // one. An account mid-attack has a recent entry and is never the victim.
    if map.len() >= MAX_TRACKED_ACCOUNTS && !map.contains_key(username) {
        map.retain(|_, (started, _)| started.elapsed() <= ATTEMPT_WINDOW);
        if map.len() >= MAX_TRACKED_ACCOUNTS {
            if let Some(oldest) = map
                .iter()
                .max_by_key(|(_, (started, _))| started.elapsed())
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest);
            }
        }
    }
    let entry = map
        .entry(username.to_string())
        .or_insert((std::time::Instant::now(), 0));
    // A quiet ten minutes forgives everything: the delay is meant to stop a
    // machine grinding through a wordlist, not to punish a person.
    if entry.0.elapsed() > ATTEMPT_WINDOW {
        *entry = (std::time::Instant::now(), 0);
    }
    entry.1 += 1;
    entry.1
}

fn forget_attempts(username: &str) {
    attempts().lock().unwrap().remove(username);
}

// ---- per-IP lockout -------------------------------------------------------
//
// The per-account throttle above only slows a guesser; the per-IP lockout stops
// one. It is keyed by the peer address, so a single machine spraying passwords
// trips it while an operator arriving from any other address is untouched — and
// a locked address is refused before the password hash runs, which is the DoS
// the hash would otherwise let one address inflict.

/// One address's recent failures: when the current window opened, how many
/// failures have landed in it, and, once tripped, until when the address is
/// locked out.
#[derive(Clone, Copy)]
struct IpRecord {
    window_started: std::time::Instant,
    failures: u32,
    locked_until: Option<std::time::Instant>,
}

/// Failed sign-ins per source address, in memory (a restart clears it, like the
/// per-account map). Bounded by [`MAX_TRACKED_IPS`].
fn ip_attempts() -> &'static std::sync::Mutex<HashMap<std::net::IpAddr, IpRecord>> {
    static IPS: OnceLock<std::sync::Mutex<HashMap<std::net::IpAddr, IpRecord>>> = OnceLock::new();
    IPS.get_or_init(Default::default)
}

/// The most source addresses whose failures we track at once. A cap, not a
/// tuning knob: a spray from many spoofable-looking addresses must not grow the
/// map without bound. Evicted the same way the account map is — quiet entries
/// first, then the least-recently-active.
const MAX_TRACKED_IPS: usize = 4096;

/// Failures within one window before an address is locked out.
const IP_MAX_FAILURES: u32 = 10;

/// How long an address stays locked once it trips the threshold.
const IP_LOCKOUT: std::time::Duration = std::time::Duration::from_secs(900);

/// How long a quiet address is forgiven — the counting window. A stray failure an
/// hour ago is not evidence of an attack now.
const IP_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);

/// The seconds an address remains locked, or `None` if it is free to try. Clears
/// a lock that has expired so the address gets a clean slate on its next attempt.
fn ip_lockout_remaining(ip: std::net::IpAddr) -> Option<u64> {
    let mut map = ip_attempts().lock().unwrap();
    let rec = map.get_mut(&ip)?;
    match rec.locked_until {
        Some(until) => {
            let now = std::time::Instant::now();
            if until > now {
                Some((until - now).as_secs().max(1))
            } else {
                // The lock has run out: forgive and let this attempt through.
                map.remove(&ip);
                None
            }
        }
        None => None,
    }
}

/// Record a failed sign-in from `ip`, opening a new window when the last one has
/// lapsed and tripping the lockout when failures reach the threshold.
fn note_ip_failure(ip: std::net::IpAddr) {
    let mut map = ip_attempts().lock().unwrap();
    // Bound the map before inserting a not-yet-seen address: forget entries whose
    // window has lapsed and which are not locked, then, if still full, evict the
    // least-recently-active. An address mid-attack has a fresh entry and is never
    // the one dropped.
    if map.len() >= MAX_TRACKED_IPS && !map.contains_key(&ip) {
        map.retain(|_, r| {
            r.locked_until.is_some() || r.window_started.elapsed() <= IP_WINDOW
        });
        if map.len() >= MAX_TRACKED_IPS {
            if let Some(oldest) = map
                .iter()
                .max_by_key(|(_, r)| r.window_started.elapsed())
                .map(|(k, _)| *k)
            {
                map.remove(&oldest);
            }
        }
    }
    let now = std::time::Instant::now();
    let rec = map.entry(ip).or_insert(IpRecord {
        window_started: now,
        failures: 0,
        locked_until: None,
    });
    // A quiet window forgives: reopen it rather than carrying an old count.
    if rec.window_started.elapsed() > IP_WINDOW && rec.locked_until.is_none() {
        rec.window_started = now;
        rec.failures = 0;
    }
    rec.failures += 1;
    if rec.failures >= IP_MAX_FAILURES {
        rec.locked_until = Some(now + IP_LOCKOUT);
    }
}

/// Clear an address after a good sign-in from it.
fn forget_ip(ip: std::net::IpAddr) {
    ip_attempts().lock().unwrap().remove(&ip);
}

/// `GET /api/v1/health` — liveness, no auth.
/// `GET /api/v1/openapi.json` — the API as OpenAPI 3.1. See [`crate::openapi`].
async fn get_openapi() -> Response {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        crate::openapi::pretty(),
    )
        .into_response()
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// Serialised-config field names that carry secret material and must never be
/// returned through the read API. Redaction is by name and by type, and it fails
/// closed: any string value under one of these keys is replaced, so a future
/// secret field that uses one of these conventional names is redacted the moment
/// it exists, and a genuinely new secret name is a one-line addition here.
///
/// Type matters for `community`: the SNMP read community is a secret *string*,
/// while a BGP `community` is a *list* of route tags that is not secret — so only
/// string-valued occurrences are redacted, which leaves the BGP list alone. The
/// GRE tunnel `key` is a `u32`, so it is likewise never touched (and not listed).
const SECRET_FIELDS: &[&str] = &[
    "secret",
    "password",
    "passphrase",
    "psk",
    "preshared-key",
    "private-key",
    "hashed-password",
    "totp",
    "community",
    "ao-key",
    "pin",
    // The update channel's entitlement (`[[update.channels]] subscription-key`):
    // a bearer token that buys tested images — anyone holding it can consume
    // the subscription, so it never leaves through the read API.
    "subscription-key",
];

/// What a redacted secret reads as in the API's config output — a marker, not an
/// empty string, so a reader can tell "a secret is set but hidden" apart from
/// "unset". This is a read-only view; the real secrets stay on disk and in the
/// config-sync push path, which serialise the [`Appliance`] directly.
const REDACTED: &str = "__redacted__";

/// Walk a serialised [`Appliance`] and replace every secret string in place, so
/// the read API leaks no key material. Recurses through objects and arrays; only
/// string values under a [`SECRET_FIELDS`] key are touched, which is what leaves
/// the BGP `community` list and the numeric GRE `key` alone.
fn redact_secrets(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if v.is_string() && SECRET_FIELDS.contains(&k.as_str()) {
                    *v = Value::String(REDACTED.to_string());
                } else {
                    redact_secrets(v);
                }
            }
        }
        Value::Array(items) => {
            for v in items.iter_mut() {
                redact_secrets(v);
            }
        }
        _ => {}
    }
}

/// `GET /api/v1/config` — the running appliance config as JSON (the same
/// [`Appliance`] the CLI edits), with every secret redacted. A read-only token
/// can reach this endpoint, so the config-sync bearer secret (which is the
/// machine's full-access API token), WireGuard private keys, IPsec PSKs, RADIUS
/// and TACACS+ secrets, the SNMP community and login password hashes / TOTP
/// secrets are all replaced by [`REDACTED`] before the config leaves the box.
async fn get_config(State(state): State<Arc<ApiState>>) -> Result<Json<Value>, ApiError> {
    let appliance = Appliance::load(&state.config_path).map_err(ApiError::internal)?;
    let mut value = serde_json::to_value(&appliance)
        .map_err(|e| ApiError::internal(anyhow!("serialising the configuration: {e}")))?;
    redact_secrets(&mut value);
    Ok(Json(value))
}

/// `PUT /api/v1/config` — replace the running config from a JSON body. This is
/// the "one config model" proof: the body is parsed+validated exactly like the
/// CLI (`Appliance::from_json`), applied to the running system through the exact
/// live-apply path a `commit` takes ([`repl::apply_live`]) — unless apply is
/// disabled (off-box) — and persisted through the same save path as the CLI
/// `save` ([`session::persist_appliance`]). A bad config is rejected (400) with
/// the validation error before anything is applied or saved.
async fn put_config(
    State(state): State<Arc<ApiState>>,
    body: String,
) -> Result<Json<Value>, ApiError> {
    // Same parse + validate the CLI runs — a semantically invalid config fails
    // here, before any live change or write.
    let appliance = Appliance::from_json(&body).map_err(ApiError::bad_request)?;

    // Same live-apply as a CLI `commit` (skipped off-box, mirroring `commit`'s
    // own `act.enabled` gate).
    if state.apply.enabled {
        // The reconcile target for a failed broad apply: the saved config on
        // disk, which still holds the previous config here (this handler applies
        // live first, persists below). `net::apply` is level-triggered, so
        // re-applying it rolls a partial failure back to last-good.
        let last_good = Appliance::load(&state.config_path).ok();
        repl::apply_live(&appliance, &state.apply, last_good.as_ref())
            .map_err(ApiError::internal)?;
    }
    // Same persist path as a CLI `save` (atomic write + revision archive). If this
    // fails AFTER a successful live apply, the running system already holds the new
    // config while the boot config still holds the old one — a reboot would then
    // silently revert the change (and any SSH-port move with it). Say that plainly
    // rather than returning a bare 500.
    if let Err(e) = session::persist_appliance(&appliance, &state.config_path, true) {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            if state.apply.enabled {
                anyhow!(
                    "the new config is APPLIED to the running system but could NOT be saved \
                     ({e:#}) — a reboot will revert to the previous config. Fix the cause and \
                     PUT again to persist it."
                )
            } else {
                anyhow!("saving the configuration failed: {e:#}")
            },
        ));
    }

    // A PUT saves as well as applies, so — like a CLI `save` — it makes the new
    // config the baseline a pending commit-confirm would revert to. Left armed,
    // that timer would "revert" to the config just saved: a no-op that silently
    // defeats the safety net. Disarm it and report that, matching the CLI `save`.
    let confirm_cancelled = if state.apply.enabled && crate::system::confirm_pending() {
        crate::system::disarm_confirm();
        true
    } else {
        false
    };

    // Record what is now running, the same running-snapshot a CLI `commit` writes,
    // so a concurrent CLI session can tell the box has moved on under it. Only when
    // it was actually applied live, and best-effort like the CLI path.
    if state.apply.enabled {
        if let Ok(toml) = appliance.to_toml() {
            let _ = crate::system::install_config_file(
                Path::new(crate::session::Session::RUNNING),
                &toml,
            );
        }
    }

    // An account that has just been given a group needs a token to exist, and
    // one whose group was taken away needs its token gone — both at the moment
    // the change is saved, not at the next restart.
    if let Err(e) = sync_user_tokens(&state) {
        eprintln!("warning: could not reconcile per-account API tokens: {e:#}");
    }
    Ok(Json(json!({
        "applied": state.apply.enabled,
        "saved": true,
        "confirm_auto_revert_cancelled": confirm_cancelled,
        "hostname": appliance.system.hostname,
        "interfaces": appliance.interfaces.len(),
        "rules": appliance.rules.len(),
    })))
}

/// `GET /api/v1/status` — hostname, service states and interfaces, the same
/// facts `sentinel show status` reports (systemd unit state + iproute2 brief).
async fn get_status(
    State(_state): State<Arc<ApiState>>,
    caller: Option<axum::Extension<Caller>>,
) -> Json<Value> {
    let you = caller.map(|axum::Extension(c)| {
        json!({
            "user": c.user,
            "permission": if c.permission.may_write() { "read-write" } else { "read-only" },
        })
    });
    // Three child processes, off the runtime — this is the endpoint the console
    // polls every five seconds, so it is the one most able to hold a worker.
    let facts = tokio::task::spawn_blocking(|| {
        json!({
            "hostname": system::current_hostname(),
            "services": {
                "firewall": service_state("velstra.service"),
                "routing": service_state("wren.service"),
            },
            "interfaces": brief_interfaces(),
        })
    })
    .await
    .unwrap_or_else(|_| json!({}));
    let mut out = json!({ "you": you });
    if let (Some(o), Some(f)) = (out.as_object_mut(), facts.as_object()) {
        for (k, v) in f {
            o.insert(k.clone(), v.clone());
        }
    }
    Json(out)
}

/// `GET /api/v1/show/*path` — proxy an operational show (e.g.
/// `/api/v1/show/ip/route`) to the existing `show` logic by invoking the same
/// binary's `show` subcommand and returning its text output. Re-executing the
/// wrapped `sentinel` preserves the tool paths the show helpers rely on.
async fn get_show(
    State(state): State<Arc<ApiState>>,
    UrlPath(path): UrlPath<String>,
) -> Result<Response, ApiError> {
    let words: Vec<String> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if words.is_empty() {
        return Err(ApiError::bad_request(anyhow!("empty show path")));
    }
    let exe = std::env::current_exe()
        .map_err(|e| ApiError::internal(anyhow!("locating the sentinel binary: {e}")))?;
    // Off the runtime. Running a child process to completion is a blocking wait,
    // and doing it on a worker thread holds that worker for as long as the child
    // lives. A console opening a section asks for every live-state pane on it at
    // once, so a handful of panes was enough to hold every worker there was —
    // and then a sign-in, or a hint, or the next page simply never got an
    // answer. The API looked hung under exactly the load it is built for.
    let config_path = state.config_path.clone();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new(exe)
            .arg("show")
            .args(&words)
            // The API can be pointed at a config other than the built-in path,
            // and every `show` it proxies has to read that same file — otherwise
            // the console serves one firewall's configuration and shows
            // another's, which renders as a page full of "nothing configured".
            .env("SENTINEL_CONFIG", &config_path)
            .output()
    })
    .await
    .map_err(|e| ApiError::internal(anyhow!("running show: {e}")))?
    .map_err(|e| ApiError::internal(anyhow!("running show: {e}")))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(ApiError::bad_request(anyhow!(if msg.is_empty() {
            "show failed".to_string()
        } else {
            msg
        })));
    }
    let body = String::from_utf8_lossy(&out.stdout).into_owned();
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response())
}

/// `POST /api/v1/configure` — run configuration commands.
///
/// The body is the same **CLI** the operator types, one command per line, and it
/// is run through the same `sentinel configure` the terminal runs. That is the
/// point: the console does not assemble a config document out of form fields —
/// it emits the identical verbs, so every validator, refusal and warning that
/// guards a typed command guards a clicked one, and there is no second grammar
/// to drift.
///
/// The caller sends its own `commit` / `save`, because "apply now" and "apply and
/// persist" are genuinely different intentions and the endpoint must not decide
/// which one was meant.
///
/// **A refused commit is reported in the output, not in the exit status** — so
/// the whole output is always returned, and a caller that only checks `ok` will
/// believe a rejected change succeeded.
async fn post_configure(
    State(state): State<Arc<ApiState>>,
    body: String,
) -> Result<Json<Value>, ApiError> {
    if body.len() > 256 * 1024 {
        return Err(ApiError::bad_request(anyhow!(
            "configuration script too large"
        )));
    }
    let exe = std::env::current_exe()
        .map_err(|e| ApiError::internal(anyhow!("locating the sentinel binary: {e}")))?;
    let config_path = state.config_path.clone();
    let no_apply = !state.apply.enabled;
    // Off the runtime, for the reason spelled out at `get_show`: a commit is the
    // longest child process this API runs.
    let out = tokio::task::spawn_blocking(move || -> std::io::Result<std::process::Output> {
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("configure").arg("--config").arg(&config_path);
        // The API's own `--no-apply` has to reach the commands it runs, or an
        // off-box instance edits the right file and then tries to reconfigure
        // the machine it is running on. Same gate the PUT handler honours.
        if no_apply {
            cmd.arg("--no-apply");
        }
        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        {
            use std::io::Write as _;
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| std::io::Error::other("configure has no stdin"))?;
            stdin.write_all(body.as_bytes())?;
        }
        child.wait_with_output()
    })
    .await
    .map_err(|e| ApiError::internal(anyhow!("running configure: {e}")))?
    .map_err(|e| ApiError::internal(anyhow!("running configure: {e}")))?;
    // Both streams: `set` errors and commit refusals go to stderr, the commit's
    // own report to stdout, and an operator needs to read them in one place.
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok(Json(json!({
        "ok": out.status.success(),
        "output": text,
    })))
}

/// `POST /api/v1/clear/*path` — run an operational `clear` command.
///
/// Separate from `show` for the reason the CLI separates them: this changes what
/// the box is doing. Separate from `configure` because it is not configuration —
/// it undoes run-time state a detector created, takes effect at once, and is
/// nowhere in the saved config, so there is nothing to stage or discard.
async fn post_clear(UrlPath(path): UrlPath<String>) -> Result<Response, ApiError> {
    let words: Vec<String> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if words.is_empty() {
        return Err(ApiError::bad_request(anyhow!("empty clear path")));
    }
    let exe = std::env::current_exe()
        .map_err(|e| ApiError::internal(anyhow!("locating the sentinel binary: {e}")))?;
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new(exe)
            .arg("clear")
            .args(&words)
            .output()
    })
    .await
    .map_err(|e| ApiError::internal(anyhow!("running clear: {e}")))?
    .map_err(|e| ApiError::internal(anyhow!("running clear: {e}")))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(ApiError::bad_request(anyhow!(if msg.is_empty() {
            "clear failed".to_string()
        } else {
            msg
        })));
    }
    let body = String::from_utf8_lossy(&out.stdout).into_owned();
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response())
}

/// `POST /api/v1/capture` — capture packets on an interface.
///
/// A `POST` although it reads nothing: it holds a process for as long as the
/// capture runs, and a `GET` that does that is one a browser or a proxy will
/// happily repeat. Bounded by [`capture::Capture`] before anything is run, so
/// the endpoint cannot be asked to hold the connection open indefinitely.
async fn post_capture(Json(req): Json<Value>) -> Result<Response, ApiError> {
    let field = |k: &str| req.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let num = |k: &str, d: u32| req.get(k).and_then(Value::as_u64).unwrap_or(d as u64) as u32;
    let capture = capture::Capture::new(
        &field("interface"),
        &field("filter"),
        num("packets", 50),
        num("seconds", 10),
    )
    .map_err(ApiError::bad_request)?;

    // Blocking work on the async runtime would stall every other request for as
    // long as the capture runs, and the whole point is that it runs for a while.
    let body = tokio::task::spawn_blocking(move || capture::run(&capture))
        .await
        .map_err(|e| ApiError::internal(anyhow!("capture task: {e}")))?
        .map_err(ApiError::bad_request)?;
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response())
}

/// `GET /api/v1/lookup/{kind}/{value}` — what is known about a value.
///
/// `asn` gives the holder of an AS number, `ptr` the name behind an address.
/// This is the appliance answering on the console's behalf: the page asks a
/// path on this box and nothing else, so a console served on an isolated
/// network keeps working — the lookup simply reports that nothing is known.
///
/// **Never an error for the caller to handle.** A field hint that turns into a
/// red banner because a registry was slow would be worse than no hint at all,
/// so a failed lookup is a 200 with `known: false`. Only a malformed request —
/// an unknown kind, a value that is not the kind it claims — is a 400.
async fn get_lookup(
    UrlPath((kind, value)): UrlPath<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    // Off the async runtime: this shells out and may wait on a network that is
    // not there, and a management API must not stall its executor for that.
    let answer = tokio::task::spawn_blocking(move || crate::lookup::lookup(&kind, &value))
        .await
        .map_err(|e| ApiError::internal(anyhow!("lookup task: {e}")))?
        .map_err(ApiError::bad_request)?;
    Ok(Json(match answer {
        Some(text) => json!({ "known": true, "answer": text }),
        None => json!({ "known": false }),
    }))
}

/// `GET /api/v1/choices/:kind` — the values this appliance has for a setting.
///
/// `kind` is `timezone`, `keyboard` or `locale`: the three settings whose valid
/// values come from packages that move on their own schedule, which is why the
/// commit-time validator reads them off this filesystem rather than out of a
/// table. The console asks the same question so its picker cannot go stale in a
/// way the validator has not.
///
/// An empty list is a perfectly good answer — a container with no zoneinfo has
/// nothing to offer — and the field it fills is a box you can still type into.
/// Only an unknown `kind` is an error.
async fn get_choices(UrlPath(kind): UrlPath<String>) -> Result<Json<Value>, ApiError> {
    // Off the async runtime: a keymap tree is a few thousand `stat` calls and
    // `locale -a` is a child process, and neither belongs on an executor that
    // is also serving the console.
    let options = tokio::task::spawn_blocking(move || crate::system::choices(&kind))
        .await
        .map_err(|e| ApiError::internal(anyhow!("choices task: {e}")))?
        .map_err(ApiError::bad_request)?;
    Ok(Json(json!({ "options": options })))
}

/// `GET /api/v1/stack` — this appliance and its config-sync peers.
///
/// A "stack" here is exactly the HA relationship the appliance already has: the
/// peers `[system.config-sync]` pushes the running config to, reached with the
/// same shared secret. Nothing new is invented to make a second box appear in
/// the console — if it is a peer, it is a member, and if it is not, the console
/// would be claiming a relationship the appliance does not actually have.
async fn get_stack(State(state): State<Arc<ApiState>>) -> Result<Json<Value>, ApiError> {
    let appliance = Appliance::load(&state.config_path).map_err(ApiError::internal)?;
    let cs = &appliance.system.config_sync;
    let mut members = vec![json!({
        "name": "self",
        "address": null,
        "hostname": system::current_hostname(),
        "reachable": true,
    })];
    for peer in &cs.peers {
        // Reachability is a real request, not a ping: the question the operator
        // has is whether this console can drive that member, and only an
        // authenticated call answers it.
        let (hostname, reachable) = match cs.secret.as_deref() {
            Some(secret) => match peer_get(cs, peer, "status", secret) {
                Ok(body) => (
                    serde_json::from_str::<Value>(&body)
                        .ok()
                        .and_then(|v| v.get("hostname")?.as_str().map(str::to_string)),
                    true,
                ),
                Err(_) => (None, false),
            },
            None => (None, false),
        };
        members.push(json!({
            "name": peer,
            "address": peer,
            "hostname": hostname,
            "reachable": reachable,
        }));
    }
    Ok(Json(json!({
        "members": members,
        "secret": cs.secret.is_some(),
    })))
}

/// `GET /api/v1/stack/:member/show/*path` — a peer's `show` output, proxied.
///
/// Proxied rather than fetched by the browser: the console is served by one
/// appliance and a peer's management port is usually not reachable from wherever
/// the operator's browser is — and making it reachable, with its own token, is a
/// worse security posture than one pane forwarding an already-authenticated
/// request over the link the two boxes already trust each other on.
async fn get_stack_show(
    State(state): State<Arc<ApiState>>,
    UrlPath((member, path)): UrlPath<(String, String)>,
) -> Result<Response, ApiError> {
    let appliance = Appliance::load(&state.config_path).map_err(ApiError::internal)?;
    let cs = &appliance.system.config_sync;
    if !cs.peers.contains(&member) {
        return Err(ApiError::bad_request(anyhow!(
            "{member} is not a stack member"
        )));
    }
    let secret = cs
        .secret
        .as_deref()
        .ok_or_else(|| ApiError::bad_request(anyhow!("no config-sync secret is set")))?;
    let body = peer_get(cs, &member, &format!("show/{path}"), secret)
        .map_err(|e| ApiError::bad_request(anyhow!("{member}: {e}")))?;
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response())
}

/// One authenticated `GET` against a peer's API — HTTPS with the peer's TLS key
/// pinned (H3), the same transport the config-sync push uses.
fn peer_get(
    cs: &crate::config::ConfigSync,
    peer: &str,
    path: &str,
    secret: &str,
) -> anyhow::Result<String> {
    let authority = crate::net::configsync_authority(peer);
    let pin = crate::net::peer_pin(cs, &authority)?;
    let url = format!("https://{authority}/api/v1/{path}");
    system::curl_get(&url, secret, 5, Some(&pin))
}

// ---- operational helpers -------------------------------------------------

/// `systemctl is-active <unit>` → `active`/`inactive`/… (best-effort text).
fn service_state(unit: &str) -> String {
    match std::process::Command::new(system::bin("systemctl"))
        .args(["is-active", unit])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => "unknown".to_string(),
    }
}

/// The `ip -brief address show` lines — the same view `show interfaces` renders.
fn brief_interfaces() -> Vec<String> {
    match std::process::Command::new(system::bin("ip"))
        .args(["-brief", "address", "show"])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|l| l.trim_end().to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}

// ---- token handling ------------------------------------------------------

/// Load the bearer token: `$SENTINEL_API_TOKEN` wins; else read `path`; else
/// generate a fresh token and write it 0600. The token never lives in the image
/// — it is minted into the persistent state dir on first run.
pub fn load_or_create_token(path: &Path) -> Result<String> {
    if let Ok(env) = std::env::var("SENTINEL_API_TOKEN") {
        let env = env.trim();
        if !env.is_empty() {
            return Ok(env.to_string());
        }
    }
    if path.exists() {
        let existing = std::fs::read_to_string(path)
            .with_context(|| format!("reading the API token {}", path.display()))?;
        let existing = existing.trim();
        if !existing.is_empty() {
            return Ok(existing.to_string());
        }
    }
    let token = generate_token()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // Create with 0600 from the outset (no world-readable window between
    // create and chmod).
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating the API token {}", path.display()))?;
    use std::io::Write;
    f.write_all(token.as_bytes())
        .with_context(|| format!("writing the API token {}", path.display()))?;
    Ok(token)
}

/// A fresh 256-bit token, URL-safe base64 (no padding) — plenty of entropy for a
/// bearer secret, and safe to paste into an `Authorization` header.
fn generate_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| anyhow!("generating a token: {e}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Whether `name` is a valid account name — the same POSIX-ish shape a
/// configured `[[system.login]]` must have (letter or `_`, then letters / digits
/// / `-` / `_`, at most 32). Used to gate any use of a request-supplied username
/// as a filename: it admits no `/`, no `.`, and nothing empty, so it cannot name
/// a path outside the tokens directory.
fn valid_account_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 32 {
        return false;
    }
    let mut chars = name.chars();
    let ok_first = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    ok_first && chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Constant-time byte comparison (length is allowed to leak; the content is
/// not). Prevents a timing side-channel on the token check.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---- error type ----------------------------------------------------------

/// A handler error rendered as `{"error": <message>}` with a status code. The
/// message is the full anyhow context chain, so a `PUT` of a bad config returns
/// the same validation error text the CLI prints.
#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(e: anyhow::Error) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: format!("{e:#}"),
        }
    }

    fn internal(e: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("{e:#}"),
        }
    }

    /// A refusal that has to name its own status: signing in distinguishes
    /// "that is not a login" (401) from "that is a login with no management
    /// access" (403), and the difference is the whole of what an operator does
    /// next.
    fn new(status: StatusCode, e: anyhow::Error) -> Self {
        Self {
            status,
            message: format!("{e:#}"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;

    const TOKEN: &str = "test-token-abc123";

    /// A throwaway config dir under the temp dir, unique per call.
    fn temp_config() -> PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("sentinel-api-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("appliance.toml")
    }

    /// Seed a config file with `hostname` and return its path in a fresh dir.
    fn seed(hostname: &str) -> PathBuf {
        let path = temp_config();
        let a = Appliance::from_toml(&format!("[system]\nhostname = \"{hostname}\"\n")).unwrap();
        session::persist_appliance(&a, &path, false).unwrap();
        path
    }

    /// State with apply DISABLED — `PUT` validates + saves but never touches the
    /// live system (no systemctl/networkd in a unit test).
    fn state(config_path: PathBuf) -> Arc<ApiState> {
        Arc::new(ApiState {
            token: TOKEN.to_string(),
            config_path,
            apply: Apply::off(),
            tokens_dir: std::env::temp_dir().join("sentinel-test-tokens"),
        })
    }

    /// The history endpoints answer the same question `show history` does, and
    /// in the same shape: a counter becomes a rate, a gauge stays a level, and
    /// a counter that was reset is a gap rather than the enormous spike that
    /// treating the wrap as a delta would draw.
    #[tokio::test]
    async fn the_history_endpoints_derive_rates_and_keep_gauges() {
        let root = std::env::temp_dir().join(format!("sentinel-hist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // SAFETY: a unit test, before any other thread reads the variable.
        unsafe { std::env::set_var("SENTINEL_METRICS_DIR", &root) };

        // A counter that climbs, then is reset.
        for (at, v) in [(1_000u64, 0u64), (1_060, 60_000), (1_120, 500)] {
            crate::metrics::record(&root, "iface.eth0.rx", at, v).unwrap();
        }
        crate::metrics::record(&root, "gauge.sessions", 1_000, 42).unwrap();
        crate::metrics::record(&root, "gauge.sessions", 1_060, 40).unwrap();

        let app = router(state(seed("fw")));
        let get = |path: String| {
            let app = app.clone();
            async move {
                let r = app
                    .oneshot(
                        Request::builder()
                            .uri(path)
                            .header("Authorization", format!("Bearer {TOKEN}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let bytes = to_bytes(r.into_body(), usize::MAX).await.unwrap();
                serde_json::from_slice::<Value>(&bytes).unwrap()
            }
        };

        let listing = get("/api/v1/metrics".into()).await;
        let names: Vec<&str> = listing["series"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(names.contains(&"iface.eth0.rx"), "got {names:?}");

        let rx = get("/api/v1/metrics/minute/iface.eth0.rx".into()).await;
        let points = rx["points"].as_array().unwrap();
        assert_eq!(points.len(), 2, "three samples make two intervals");
        assert_eq!(
            points[0]["value"].as_f64().unwrap(),
            1000.0,
            "60000 B over 60 s"
        );
        assert!(
            points[1]["value"].is_null(),
            "the counter reset must be a gap, got {:?}",
            points[1]["value"]
        );

        // A gauge is a level: it must come back as it was stored, not as the
        // change in it.
        let g = get("/api/v1/metrics/minute/gauge.sessions".into()).await;
        let gp = g["points"].as_array().unwrap();
        assert_eq!(gp.len(), 2, "a gauge keeps every sample");
        assert_eq!(gp[0]["value"].as_u64().unwrap(), 42);
        assert_eq!(gp[1]["value"].as_u64().unwrap(), 40);

        let bad = get("/api/v1/metrics/nonsense/iface.eth0.rx".into()).await;
        assert!(bad["error"].is_string(), "an unknown resolution is refused");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The Prometheus scrape target lives behind the same bearer auth as the rest
    /// and answers in the text exposition format. Interface counters come from the
    /// host's own `/proc/net/dev`, so this asserts the transport (auth, status,
    /// content type, well-formedness) rather than a fixed series.
    #[tokio::test]
    async fn the_prometheus_endpoint_is_authed_and_well_formed() {
        let st = state(seed("fw"));

        // No token: refused, exactly like every other protected endpoint.
        let unauth = router(st.clone())
            .oneshot(get("/metrics", None))
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        // With a token: 200, Prometheus content type, and — since the test host
        // has interfaces in /proc/net/dev — at least one counter family, each
        // sample line naming its metric with a labelled value.
        let resp = router(st)
            .oneshot(get("/metrics", Some(TOKEN)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(ct.starts_with("text/plain"), "content type was {ct:?}");
        let body = body_string(resp).await;
        // Every HELP line is matched by a TYPE line for the same family, and no
        // sample line is orphaned without its header.
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                assert!(
                    rest.ends_with(" counter") || rest.ends_with(" gauge"),
                    "unexpected metric type line {line:?}"
                );
            }
        }
        if body.contains("sentinel_interface_receive_bytes_total") {
            assert!(
                body.contains("# TYPE sentinel_interface_receive_bytes_total counter"),
                "a sample without its TYPE header: {body}"
            );
        }
    }

    /// The per-IP limiter counts within a window, trips a lockout at the
    /// threshold, and forgets an address on demand. A distinctive TEST-NET-3
    /// address keeps it clear of any other test sharing the process-global map.
    #[test]
    fn the_per_ip_lockout_trips_at_the_threshold() {
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        forget_ip(ip);
        // One below the threshold: still free to try.
        for _ in 0..IP_MAX_FAILURES - 1 {
            note_ip_failure(ip);
        }
        assert!(
            ip_lockout_remaining(ip).is_none(),
            "{} failures must not lock yet",
            IP_MAX_FAILURES - 1
        );
        // The failure that reaches the threshold locks the address.
        note_ip_failure(ip);
        let remaining = ip_lockout_remaining(ip).expect("the threshold must lock the address");
        assert!(
            remaining > 0 && remaining <= IP_LOCKOUT.as_secs(),
            "a fresh lock counts down from the full window, got {remaining}"
        );
        // A neighbouring address is untouched — the lockout is per address.
        let other: std::net::IpAddr = "203.0.113.99".parse().unwrap();
        assert!(ip_lockout_remaining(other).is_none());
        // Forgetting clears it.
        forget_ip(ip);
        assert!(ip_lockout_remaining(ip).is_none());
    }

    /// The handler reads `ConnectInfo` and refuses a locked address up front — the
    /// point being that the refusal comes *before* the password hash, so a locked
    /// guesser cannot make the box spend that work. Proven by pre-loading the
    /// limiter for an address, then driving one login from it and seeing 429.
    #[tokio::test]
    async fn a_locked_address_is_refused_with_429() {
        let ip: std::net::IpAddr = "203.0.113.8".parse().unwrap();
        forget_ip(ip);
        for _ in 0..IP_MAX_FAILURES {
            note_ip_failure(ip);
        }
        assert!(ip_lockout_remaining(ip).is_some(), "precondition: locked");

        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/login")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"username":"admin","password":"whatever"}"#))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 8], 5555))));

        let resp = router(state(seed("fw"))).oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a locked address must be refused before anything else"
        );
        forget_ip(ip);
    }

    /// With no `ConnectInfo` at all — an in-process oneshot, a peer-less transport
    /// — the per-IP limiter is simply skipped and the login proceeds on the
    /// per-account throttle alone. It must not error for want of an address.
    #[tokio::test]
    async fn a_login_without_connect_info_still_works() {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/login")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"username":"","password":""}"#))
            .unwrap();
        let resp = router(state(seed("fw"))).oneshot(req).await.unwrap();
        // An empty username/password is a bad request, NOT a 500 and NOT a 429:
        // the missing ConnectInfo was tolerated and the handler ran normally.
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// A second factor is checked *after* the password and never instead of it,
    /// so an account with a code is not a way to get in without one — and a
    /// wrong code is the same refusal as a wrong password, which is what stops
    /// somebody probing which half they got right.
    #[test]
    fn an_account_with_a_second_factor_needs_both() {
        // The RFC 6238 secret, so the expected code is computable here rather
        // than being whatever the implementation happens to produce.
        const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let hash = crate::passwd::hash("a-good-password").expect("hashing works here");
        let path = temp_config();
        let a = Appliance::from_toml(&format!(
            "[system]\nhostname = \"fw\"\n\
             [[system.group]]\nname = \"ops\"\npermission = \"read-write\"\n\
             [[system.login]]\nusername = \"vera\"\n\
             hashed-password = \"{hash}\"\ntotp = \"{SECRET}\"\ngroup = \"ops\"\n"
        ))
        .expect("the configuration parses");
        session::persist_appliance(&a, &path, false).unwrap();
        let st = state(path);

        // The right password with no code is refused, and says what is missing.
        let err = sign_in(&st, "vera", "a-good-password", "").expect_err("no code");
        assert!(
            format!("{err:?}").contains("one-time code"),
            "the refusal does not say a code is needed: {err:?}"
        );

        // A wrong code is refused the same way a wrong password is.
        assert!(sign_in(&st, "vera", "a-good-password", "000001").is_err());

        // The right code lets them in…
        let now = crate::aaa::unix_now();
        let code = crate::aaa::totp_at(SECRET, now).expect("the secret decodes");
        let session = sign_in(&st, "vera", "a-good-password", &code)
            .unwrap_or_else(|e| panic!("both factors were refused: {e:?}"));
        assert_eq!(session["user"], "vera");
        assert_eq!(session["permission"], "read-write");

        // …and the code alone does not, because the password is still checked.
        assert!(sign_in(&st, "vera", "wrong", &code).is_err());
    }

    /// The machine token is full access and has no account behind it — it is
    /// what a peer firewall presents when config-sync pushes a commit, and what
    /// an operator has before any account exists.
    #[test]
    fn the_machine_token_is_full_access_and_nameless() {
        let dir = tempdir();
        let cfg = dir.join("appliance.toml");
        std::fs::write(&cfg, "[system]\nhostname = \"fw\"\n").unwrap();
        let st = state(cfg);
        let caller = resolve_caller(&st, TOKEN).expect("the machine token was refused");
        assert_eq!(caller.user, None);
        assert!(caller.permission.may_write());
        // …and anything else is nobody.
        assert!(resolve_caller(&st, "not-the-token").is_none());
    }

    /// A token file is only the secret; the **configuration** is the authority.
    /// An account whose group was taken away therefore grants nothing, even
    /// though its token file is still on disk and still matches.
    #[test]
    fn a_withdrawn_group_withdraws_access() {
        let dir = tempdir();
        let cfg = dir.join("appliance.toml");
        let tokens = dir.join("tokens");
        std::fs::create_dir_all(&tokens).unwrap();
        std::fs::write(tokens.join("alice"), "alice-secret\n").unwrap();

        let st = ApiState {
            token: TOKEN.to_string(),
            config_path: cfg.clone(),
            apply: Apply::off(),
            tokens_dir: tokens,
        };

        // With the group: read-only, and named.
        std::fs::write(
            &cfg,
            "[system]\nhostname = \"fw\"\n\
             [[system.group]]\nname = \"viewers\"\npermission = \"read-only\"\n\
             [[system.login]]\nusername = \"alice\"\ngroup = \"viewers\"\n",
        )
        .unwrap();
        let caller = resolve_caller(&st, "alice-secret").expect("alice was refused");
        assert_eq!(caller.user.as_deref(), Some("alice"));
        assert!(!caller.permission.may_write());

        // Group removed from the account: the same token now resolves to nobody.
        std::fs::write(
            &cfg,
            "[system]\nhostname = \"fw\"\n\
             [[system.group]]\nname = \"viewers\"\npermission = \"read-only\"\n\
             [[system.login]]\nusername = \"alice\"\n",
        )
        .unwrap();
        assert!(resolve_caller(&st, "alice-secret").is_none());
    }

    /// Minting adds what has been granted and removes what has not — the second
    /// half matters more: a token file left behind after the group was taken
    /// away would be an access nobody can see in the configuration.
    #[test]
    fn tokens_appear_and_are_withdrawn_with_the_grant() {
        let dir = tempdir();
        let cfg = dir.join("appliance.toml");
        let tokens = dir.join("tokens");
        let st = ApiState {
            token: TOKEN.to_string(),
            config_path: cfg.clone(),
            apply: Apply::off(),
            tokens_dir: tokens.clone(),
        };

        std::fs::write(
            &cfg,
            "[system]\nhostname = \"fw\"\n\
             [[system.group]]\nname = \"ops\"\npermission = \"read-write\"\n\
             [[system.login]]\nusername = \"bob\"\ngroup = \"ops\"\n",
        )
        .unwrap();
        sync_user_tokens(&st).unwrap();
        let minted = std::fs::read_to_string(tokens.join("bob")).unwrap();
        assert!(!minted.trim().is_empty());

        // Minting again leaves it alone: rotating on every apply would log every
        // client out whenever anything at all was committed.
        sync_user_tokens(&st).unwrap();
        assert_eq!(std::fs::read_to_string(tokens.join("bob")).unwrap(), minted);

        std::fs::write(&cfg, "[system]\nhostname = \"fw\"\n").unwrap();
        sync_user_tokens(&st).unwrap();
        assert!(!tokens.join("bob").exists(), "the token outlived the grant");
    }

    /// A scratch directory of this test's own, since these write real files.
    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "sentinel-rbac-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    async fn body_string(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn get(uri: &str, token: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().method("GET").uri(uri);
        if let Some(t) = token {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        b.body(Body::empty()).unwrap()
    }

    fn put(uri: &str, token: &str, json: &str) -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn health_needs_no_auth() {
        let st = state(seed("seed-host"));
        let resp = router(st)
            .oneshot(get("/api/v1/health", None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("ok"));
    }

    /// The document a client reads before it has a token, so it is open like
    /// `health` — and it is the router's own routes, or the check in
    /// `openapi.rs` would have failed first.
    #[tokio::test]
    async fn the_openapi_document_needs_no_auth_and_names_the_trace() {
        let st = state(seed("seed-host"));
        let resp = router(st)
            .oneshot(get("/api/v1/openapi.json", None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        let doc: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(doc["openapi"], "3.1.0");
        assert!(doc["paths"]["/api/v1/trace"]["get"].is_object());
    }

    /// The closed sets the console's pickers are filled from. Behind the token
    /// like everything else, an unknown kind is a 400 rather than an empty
    /// list — a picker that is quietly empty because the console asked for
    /// something that does not exist is the failure that looks like success.
    #[tokio::test]
    async fn choices_answer_with_a_list_and_refuse_a_kind_they_do_not_have() {
        let st = state(seed("seed-host"));
        let resp = router(st.clone())
            .oneshot(get("/api/v1/choices/timezone", Some(TOKEN)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        let parsed: Value = serde_json::from_str(&body).expect("json");
        assert!(parsed["options"].is_array(), "{body}");

        let resp = router(st.clone())
            .oneshot(get("/api/v1/choices/timezone", None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = router(st)
            .oneshot(get("/api/v1/choices/nonsense", Some(TOKEN)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rejects_missing_token() {
        let st = state(seed("seed-host"));
        let resp = router(st)
            .oneshot(get("/api/v1/config", None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_wrong_token() {
        let st = state(seed("seed-host"));
        let resp = router(st)
            .oneshot(get("/api/v1/config", Some("not-the-token")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_config_roundtrips_the_model() {
        let st = state(seed("round-trip-host"));
        let resp = router(st)
            .oneshot(get("/api/v1/config", Some(TOKEN)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // The body is the real Appliance JSON; parse it back and check the model.
        let a = Appliance::from_json(&body_string(resp).await).unwrap();
        assert_eq!(a.system.hostname, "round-trip-host");
    }

    /// A read-only caller can reach `GET /config`, so the config it returns must
    /// carry no secret material: the config-sync bearer secret (which IS the
    /// machine's full-access API token), RADIUS secrets, login password hashes
    /// and TOTP secrets are all redacted before the config leaves the box.
    #[tokio::test]
    async fn get_config_redacts_every_secret() {
        let path = temp_config();
        let hash = crate::passwd::hash("a-good-password").expect("hashing works here");
        let toml = format!(
            "[system]\nhostname = \"fw\"\n\
             [system.config-sync]\npeer = [\"10.0.0.2\"]\nsecret = \"machine-token-s3cret\"\n\
             [[system.aaa.radius]]\nserver = \"10.0.0.9\"\nsecret = \"radius-shared-secret\"\n\
             [[system.aaa.tacacs]]\nserver = \"10.0.0.10\"\nsecret = \"tacacs-shared-secret\"\n\
             [[system.group]]\nname = \"ops\"\npermission = \"read-write\"\n\
             [[system.login]]\nusername = \"vera\"\n\
             hashed-password = \"{hash}\"\ntotp = \"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\"\ngroup = \"ops\"\n"
        );
        let a = Appliance::from_toml(&toml).expect("the configuration parses");
        session::persist_appliance(&a, &path, false).unwrap();
        let st = state(path);

        let resp = router(st)
            .oneshot(get("/api/v1/config", Some(TOKEN)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;

        // Not one byte of any secret survives the read path…
        for leaked in [
            "machine-token-s3cret",
            "radius-shared-secret",
            "tacacs-shared-secret",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            hash.as_str(),
        ] {
            assert!(
                !body.contains(leaked),
                "GET /config leaked a secret ({leaked:?}): {body}"
            );
        }
        // …and the redaction marker is there in their place, so the reader can
        // still tell that a secret is set.
        assert!(
            body.contains(REDACTED),
            "secrets should be replaced by the redaction marker: {body}"
        );
        // Non-secret structure is untouched.
        let parsed: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(parsed["system"]["hostname"], "fw");
    }

    /// The subscription key is an entitlement — whoever holds it can consume
    /// the subscription — so it must never leave over the API, in any channel,
    /// however the config was written. The redaction marker takes its place so
    /// a reader can still see that a key IS configured.
    #[tokio::test]
    async fn a_subscription_key_never_leaves_over_the_api() {
        let path = temp_config();
        let toml = "[system]\nhostname = \"fw\"\n\
             [update]\nchannel = \"enterprise\"\n\
             [[update.channels]]\nname = \"community\"\n\
             url = \"https://updates.example.test/community\"\n\
             public-key = \"file:/etc/sentinel/community.pem\"\n\
             [[update.channels]]\nname = \"enterprise\"\n\
             url = \"https://updates.example.test/enterprise\"\n\
             public-key = \"file:/etc/sentinel/enterprise.pem\"\n\
             subscription-key = \"velstra-ent-9f2c-SECRET\"\n";
        let a = Appliance::from_toml(toml).expect("the configuration parses");
        session::persist_appliance(&a, &path, false).unwrap();
        let st = state(path);

        let resp = router(st)
            .oneshot(get("/api/v1/config", Some(TOKEN)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(
            !body.contains("velstra-ent-9f2c-SECRET"),
            "GET /config leaked the subscription key: {body}"
        );
        let parsed: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(
            parsed["update"]["channels"][1]["subscription-key"], REDACTED,
            "the key reads as redacted, not as absent: {body}"
        );
        // The rest of the channel is readable — only the entitlement is hidden.
        assert_eq!(parsed["update"]["channel"], "enterprise");
        assert_eq!(
            parsed["update"]["channels"][1]["url"],
            "https://updates.example.test/enterprise"
        );
    }

    #[tokio::test]
    async fn put_invalid_returns_validation_error_and_does_not_apply() {
        let path = seed("seed-host");
        let st = state(path.clone());
        // Structurally valid JSON, semantically invalid (a space + '!' in the
        // hostname) — must fail the SAME validation the CLI runs.
        let resp = router(st)
            .oneshot(put(
                "/api/v1/config",
                TOKEN,
                r#"{"system":{"hostname":"Bad Host!"}}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_string(resp).await;
        assert!(
            body.contains("hostname"),
            "error should name the field: {body}"
        );
        // Not applied: the saved config is untouched.
        let still = Appliance::load(&path).unwrap();
        assert_eq!(still.system.hostname, "seed-host");
    }

    #[tokio::test]
    async fn put_valid_updates_the_saved_config() {
        let path = seed("seed-host");
        let st = state(path.clone());
        let resp = router(st.clone())
            .oneshot(put(
                "/api/v1/config",
                TOKEN,
                r#"{"system":{"hostname":"put-host"}}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // The model on disk now reflects the PUT (proving it went through the
        // shared persist path).
        let saved = Appliance::load(&path).unwrap();
        assert_eq!(saved.system.hostname, "put-host");
        // And a subsequent GET returns the new config.
        let resp = router(st)
            .oneshot(get("/api/v1/config", Some(TOKEN)))
            .await
            .unwrap();
        let a = Appliance::from_json(&body_string(resp).await).unwrap();
        assert_eq!(a.system.hostname, "put-host");
    }
}
