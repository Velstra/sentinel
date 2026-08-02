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
//! endpoint except `/health`. The server binds localhost by default; widen it
//! with `--listen 0.0.0.0:<port>`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::{Path as UrlPath, Request, State},
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
    /// The bearer token every request (except `/health`) must present.
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
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    eprintln!(
        "sentinel api listening on http://{addr} (bearer-token auth; token at {})",
        token_file.display()
    );
    axum::serve(listener, app)
        .await
        .context("serving the REST API")?;
    Ok(())
}

/// Build the API router. `/health` is unauthenticated; everything else sits
/// behind the bearer-token middleware.
pub fn router(state: Arc<ApiState>) -> Router {
    let protected = Router::new()
        .route("/api/v1/config", get(get_config).put(put_config))
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/show/*path", get(get_show))
        .route("/api/v1/rule-hits", get(get_rule_hits))
        .route("/api/v1/metrics", get(get_metrics_list))
        .route("/api/v1/metrics/:resolution/:series", get(get_metrics))
        .route("/api/v1/configure", post(post_configure))
        .route("/api/v1/clear/*path", post(post_clear))
        .route("/api/v1/capture", post(post_capture))
        // What the appliance can tell you about a value you are typing. The
        // console never reaches outside itself; it asks here, and this asks the
        // world — which is why a page served on an isolated network still works.
        .route("/api/v1/lookup/:kind/:value", get(get_lookup))
        .route("/api/v1/stack", get(get_stack))
        .route("/api/v1/stack/:member/show/*path", get(get_stack_show))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token));
    Router::new()
        .route("/api/v1/health", get(health))
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
        .merge(protected)
        .with_state(state)
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
        if !ct_eq(presented.as_bytes(), stored.trim().as_bytes()) {
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
/// Failures are slowed and counted. Not a lockout — locking an administrator
/// out of their own firewall is a denial of service anyone can trigger — but
/// enough that guessing over the network is not a practical way in.
async fn post_login(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
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
    let state = state.clone();
    // Off the runtime: hashing is deliberately slow, and a login must not stall
    // the executor that is serving everybody else.
    let outcome = tokio::task::spawn_blocking(move || sign_in(&state, &username, &password, &code))
        .await
        .map_err(|e| ApiError::internal(anyhow!("login task: {e}")))?;
    match outcome {
        Ok(session) => Ok(Json(session)),
        Err(refusal) => Err(refusal),
    }
}

/// Ask each configured server in turn, and say whether one of them accepted.
///
/// The distinction that matters: a server that **rejects** has answered, and no
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
) -> Result<bool, ApiError> {
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
            Ok(accepted) => return Ok(accepted),
            Err(e) => {
                eprintln!(
                    "warning: RADIUS server {} did not answer: {e}",
                    server.server
                );
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
    // Guessing costs time whether or not the account exists, so a wrong
    // username and a wrong password are indistinguishable from the outside.
    let attempts = note_attempt(username);
    std::thread::sleep(std::time::Duration::from_millis(
        250 * attempts.min(8) as u64,
    ));

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
        if aaa.radius.is_empty() {
            // No directory to fall back to, so the local answer is the answer.
            return Err(if login.is_some_and(|l| l.hashed_password.is_none()) {
                ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    anyhow!("that account has no password set"),
                )
            } else {
                refused()
            });
        }
        if !ask_the_directory(aaa, &appliance.system.hostname, username, password)? {
            return Err(refused());
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

fn note_attempt(username: &str) -> u32 {
    let mut map = attempts().lock().unwrap();
    let entry = map
        .entry(username.to_string())
        .or_insert((std::time::Instant::now(), 0));
    // A quiet ten minutes forgives everything: the delay is meant to stop a
    // machine grinding through a wordlist, not to punish a person.
    if entry.0.elapsed() > std::time::Duration::from_secs(600) {
        *entry = (std::time::Instant::now(), 0);
    }
    entry.1 += 1;
    entry.1
}

fn forget_attempts(username: &str) {
    attempts().lock().unwrap().remove(username);
}

/// `GET /api/v1/health` — liveness, no auth.
async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// `GET /api/v1/config` — the full running appliance config as JSON (the same
/// [`Appliance`] the CLI edits).
async fn get_config(State(state): State<Arc<ApiState>>) -> Result<Json<Appliance>, ApiError> {
    let appliance = Appliance::load(&state.config_path).map_err(ApiError::internal)?;
    Ok(Json(appliance))
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
        repl::apply_live(&appliance, &state.apply).map_err(ApiError::internal)?;
    }
    // Same persist path as a CLI `save` (atomic write + revision archive).
    session::persist_appliance(&appliance, &state.config_path, true).map_err(ApiError::internal)?;

    // An account that has just been given a group needs a token to exist, and
    // one whose group was taken away needs its token gone — both at the moment
    // the change is saved, not at the next restart.
    if let Err(e) = sync_user_tokens(&state) {
        eprintln!("warning: could not reconcile per-account API tokens: {e:#}");
    }
    Ok(Json(json!({
        "applied": state.apply.enabled,
        "saved": true,
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
    Json(json!({
        "you": you,
        "hostname": system::current_hostname(),
        "services": {
            "firewall": service_state("velstra.service"),
            "routing": service_state("wren.service"),
        },
        "interfaces": brief_interfaces(),
    }))
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
    let out = std::process::Command::new(exe)
        .arg("show")
        .args(&words)
        // The API can be pointed at a config other than the built-in path, and
        // every `show` it proxies has to read that same file — otherwise the
        // console serves one firewall's configuration and shows another's, which
        // renders as a page full of "nothing configured".
        .env("SENTINEL_CONFIG", &state.config_path)
        .output()
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
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("configure").arg("--config").arg(&state.config_path);
    // The API's own `--no-apply` has to reach the commands it runs, or an
    // off-box instance edits the right file and then tries to reconfigure the
    // machine it is running on. Same gate the PUT handler honours.
    if !state.apply.enabled {
        cmd.arg("--no-apply");
    }
    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| ApiError::internal(anyhow!("running configure: {e}")))?;
    {
        use std::io::Write as _;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| ApiError::internal(anyhow!("configure has no stdin")))?;
        stdin
            .write_all(body.as_bytes())
            .map_err(|e| ApiError::internal(anyhow!("feeding configure: {e}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| ApiError::internal(anyhow!("waiting for configure: {e}")))?;
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
    let out = std::process::Command::new(exe)
        .arg("clear")
        .args(&words)
        .output()
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
            Some(secret) => match peer_get(peer, "status", secret) {
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
    let body = peer_get(&member, &format!("show/{path}"), secret)
        .map_err(|e| ApiError::bad_request(anyhow!("{member}: {e}")))?;
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response())
}

/// One authenticated `GET` against a peer's API.
fn peer_get(peer: &str, path: &str, secret: &str) -> anyhow::Result<String> {
    let url = format!(
        "http://{}/api/v1/{path}",
        crate::net::configsync_authority(peer)
    );
    system::curl_get(&url, secret, 5)
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
