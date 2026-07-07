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
//!
//! Auth is a bearer token (0600 file or `$SENTINEL_API_TOKEN`), required on every
//! endpoint except `/health`. The server binds localhost by default; widen it
//! with `--listen 0.0.0.0:<port>`.

use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::{Path as UrlPath, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::Engine;
use serde_json::{Value, json};

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
    });
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
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token));
    Router::new()
        .route("/api/v1/health", get(health))
        .merge(protected)
        .with_state(state)
}

// ---- middleware ----------------------------------------------------------

/// Reject any request whose `Authorization: Bearer <token>` does not match the
/// configured token. The comparison is constant-time so a wrong token leaks no
/// timing signal about how many bytes were right.
async fn require_token(State(state): State<Arc<ApiState>>, req: Request, next: Next) -> Response {
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match provided {
        Some(t) if ct_eq(t.as_bytes(), state.token.as_bytes()) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing or invalid bearer token" })),
        )
            .into_response(),
    }
}

// ---- handlers ------------------------------------------------------------

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
async fn get_status(State(_state): State<Arc<ApiState>>) -> Json<Value> {
    Json(json!({
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
async fn get_show(UrlPath(path): UrlPath<String>) -> Result<Response, ApiError> {
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
        })
    }

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
