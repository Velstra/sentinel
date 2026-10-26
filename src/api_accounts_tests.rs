//! Signing in, the sessions it opens, and the throttle in front of it.
//!
//! Kept beside `api.rs` rather than in its test module because these tests
//! need a directory that answers on demand and a bench of their own — a token
//! directory no other test reconciles underneath them.

use super::*;
use axum::body::Body;
use axum::http::Request;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

/// The session limits these tests hold the implementation to: thirty idle
/// minutes, twelve hours in all.
const IDLE: u64 = 30 * 60;
const LIFETIME: u64 = 12 * 60 * 60;

const PASSWORD: &str = "a-good-password";

/// A directory that accepts one username and password and refuses everything
/// else, and counts how often it was asked — the count is how a test sees
/// how many passwords were actually checked.
struct FakeDirectory {
    accepts: Option<(&'static str, &'static str)>,
    calls: AtomicUsize,
}

impl FakeDirectory {
    fn new(accepts: Option<(&'static str, &'static str)>) -> Arc<Self> {
        Arc::new(Self {
            accepts,
            calls: AtomicUsize::new(0),
        })
    }
}

impl Authenticator for FakeDirectory {
    fn consult(
        &self,
        _aaa: &crate::config::Aaa,
        _hostname: &str,
        username: &str,
        password: &str,
    ) -> Result<Consulted, ApiError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.accepts {
            Some((u, p)) if u == username && p == password => Ok(Consulted::Accepted),
            _ => Ok(Consulted::RejectedBy("TACACS+")),
        }
    }
}

/// A scratch directory with a config file and a token directory of its own.
fn bench(config: &str, directory: Arc<dyn Authenticator>) -> Arc<ApiState> {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sentinel-accounts-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("appliance.toml");
    std::fs::write(&config_path, config).unwrap();
    Arc::new(ApiState {
        telemetry: Arc::default(),
        token: "machine-token-for-accounts-tests".into(),
        token_path: None,
        tls_pin: None,
        config_path,
        apply: Apply::off(),
        tokens_dir: dir.join("api-tokens"),
        directory,
    })
}

fn rewrite(st: &ApiState, config: &str) {
    std::fs::write(&st.config_path, config).unwrap();
}

fn hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| crate::passwd::hash(PASSWORD).expect("openssl hashes here"))
}

/// One local read-write account, `vera`, and a read-only group for the
/// directory to hand out.
fn local_config(hash: &str, extra: &str) -> String {
    format!(
        "[system]\nhostname = \"fw\"\n\
         [[system.group]]\nname = \"ops\"\npermission = \"read-write\"\n\
         [[system.group]]\nname = \"viewers\"\npermission = \"read-only\"\n\
         [[system.login]]\nusername = \"vera\"\nhashed-password = \"{hash}\"\n\
         group = \"ops\"\n{extra}"
    )
}

/// A box that knows nobody locally and sends everyone to TACACS+, handing
/// what it accepts the `viewers` group.
fn directory_config(default_group: Option<&str>) -> String {
    let default_group = default_group
        .map(|g| format!("default-group = \"{g}\"\n"))
        .unwrap_or_default();
    format!(
        "[system]\nhostname = \"fw\"\n\
         [[system.group]]\nname = \"viewers\"\npermission = \"read-only\"\n\
         [[system.group]]\nname = \"ops\"\npermission = \"read-write\"\n\
         [system.aaa]\n{default_group}\
         [[system.aaa.tacacs]]\nserver = \"192.0.2.10\"\nsecret = \"tacacs-shared\"\n"
    )
}

fn token_of(session: &Value) -> String {
    session["token"].as_str().expect("a token").to_string()
}

fn bearer(method: &str, uri: &str, token: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn status_of(st: &Arc<ApiState>, request: Request<Body>) -> StatusCode {
    router(st.clone()).oneshot(request).await.unwrap().status()
}

// ---- directory sign-ins (#16) ----------------------------------------------

/// A directory account has no `[[system.login]]` entry — that is what makes it
/// a directory account — and the token its sign-in hands back must still work
/// on the next request, with the default group's permission, after the
/// reconciliation every commit runs, and only until that grant is withdrawn.
#[tokio::test]
async fn a_directory_sign_in_reaches_the_api_with_its_granted_permission() {
    let directory = FakeDirectory::new(Some(("dirk", "dir-pass-1")));
    let st = bench(&directory_config(Some("viewers")), directory);
    let session = sign_in(&st, "dirk", "dir-pass-1", "").expect("the directory accepted");
    assert_eq!(session["permission"], "read-only");
    let token = token_of(&session);

    assert_eq!(
        status_of(&st, bearer("GET", "/api/v1/config", &token, "")).await,
        StatusCode::OK,
        "a directory session was refused on its first request"
    );
    // Read-only, as granted: a write is known-and-refused, not unknown.
    assert_eq!(
        status_of(
            &st,
            bearer(
                "PUT",
                "/api/v1/config",
                &token,
                r#"{"system":{"hostname":"x"}}"#
            )
        )
        .await,
        StatusCode::FORBIDDEN
    );

    // Every commit reconciles the token directory. A directory session is not
    // an account the configuration lists, and it must not be swept for that.
    sync_user_tokens(&st).unwrap();
    let caller = resolve_caller(&st, &token).expect("reconciliation removed a directory session");
    assert_eq!(caller.user.as_deref(), Some("dirk"));
    assert!(!caller.permission.may_write());

    // Withdrawing the default group withdraws what it granted.
    rewrite(&st, &directory_config(None));
    assert!(resolve_caller(&st, &token).is_none());
}

/// Raising the default group's permission does not silently upgrade a session
/// that was granted less: the session ends and the next sign-in gets the new
/// grant.
#[test]
fn a_changed_default_group_ends_directory_sessions() {
    let directory = FakeDirectory::new(Some(("dirk", "dir-pass-1")));
    let st = bench(&directory_config(Some("viewers")), directory);
    let token = token_of(&sign_in(&st, "dirk", "dir-pass-1", "").unwrap());
    assert!(resolve_caller(&st, &token).is_some());
    rewrite(&st, &directory_config(Some("ops")));
    assert!(resolve_caller(&st, &token).is_none());
    sync_user_tokens(&st).unwrap();
    let again = sign_in(&st, "dirk", "dir-pass-1", "").unwrap();
    assert_eq!(again["permission"], "read-write");
}

// ---- sessions (#17) --------------------------------------------------------

/// Every sign-in opens its own session: two browsers are two tokens, and
/// signing one out leaves the other alone.
#[tokio::test]
async fn each_sign_in_is_its_own_session_and_sign_out_ends_only_that_one() {
    let st = bench(&local_config(hash(), ""), Arc::new(ConfiguredServers));
    let first = token_of(&sign_in(&st, "vera", PASSWORD, "").unwrap());
    let second = token_of(&sign_in(&st, "vera", PASSWORD, "").unwrap());
    assert_ne!(first, second, "two sign-ins shared one token");

    assert_eq!(
        status_of(&st, bearer("POST", "/api/v1/sign-out", &first, "")).await,
        StatusCode::OK
    );
    assert_eq!(
        status_of(&st, bearer("GET", "/api/v1/config", &first, "")).await,
        StatusCode::UNAUTHORIZED,
        "a signed-out token still worked"
    );
    assert_eq!(
        status_of(&st, bearer("GET", "/api/v1/config", &second, "")).await,
        StatusCode::OK,
        "signing one session out ended the other"
    );
}

/// A read-only account can sign itself out: ending a session is not a write
/// to anything the permission protects.
#[tokio::test]
async fn a_read_only_session_can_sign_out() {
    let directory = FakeDirectory::new(Some(("dirk", "dir-pass-1")));
    let st = bench(&directory_config(Some("viewers")), directory);
    let token = token_of(&sign_in(&st, "dirk", "dir-pass-1", "").unwrap());
    assert_eq!(
        status_of(&st, bearer("POST", "/api/v1/sign-out", &token, "")).await,
        StatusCode::OK
    );
    assert!(resolve_caller(&st, &token).is_none());
}

/// The machine token is not a session. Signing it "out" must neither work
/// nor be mistaken for having worked — it is rotated, not ended.
#[tokio::test]
async fn the_machine_token_cannot_be_signed_out() {
    let st = bench(&local_config(hash(), ""), Arc::new(ConfiguredServers));
    let machine = st.token.clone();
    assert_eq!(
        status_of(&st, bearer("POST", "/api/v1/sign-out", &machine, "")).await,
        StatusCode::BAD_REQUEST
    );
    assert!(resolve_caller(&st, &machine).is_some());
    // …and it never idles out.
    assert!(resolve_caller_at(&st, &machine, crate::aaa::unix_now() + 10 * LIFETIME).is_some());
}

/// Use keeps a session alive; thirty quiet minutes end it.
#[test]
fn a_session_lives_while_used_and_ends_when_idle() {
    let st = bench(&local_config(hash(), ""), Arc::new(ConfiguredServers));
    let token = token_of(&sign_in(&st, "vera", PASSWORD, "").unwrap());
    let start = crate::aaa::unix_now();
    // Used every twenty minutes for an hour: each use is inside the idle
    // window of the one before, so the session is never idle.
    for step in 1..=3 {
        assert!(
            resolve_caller_at(&st, &token, start + step * 20 * 60).is_some(),
            "a session in steady use ended after {} minutes",
            step * 20
        );
    }
    let last = start + 60 * 60;
    assert!(resolve_caller_at(&st, &token, last + IDLE + 1).is_none());
    // Once ended, it stays ended even if the clock is read again earlier.
    assert!(resolve_caller_at(&st, &token, last + 60).is_none());
}

/// However busy, a session ends twelve hours after the sign-in that opened it.
#[test]
fn a_session_ends_at_its_lifetime_however_busy() {
    let st = bench(&local_config(hash(), ""), Arc::new(ConfiguredServers));
    let token = token_of(&sign_in(&st, "vera", PASSWORD, "").unwrap());
    let start = crate::aaa::unix_now();
    let mut at = start;
    while at + 10 * 60 < start + LIFETIME {
        at += 10 * 60;
        assert!(resolve_caller_at(&st, &token, at).is_some());
    }
    assert!(resolve_caller_at(&st, &token, start + LIFETIME + 1).is_none());
}

/// Changing what an account is — its password, its second factor, its group,
/// or whether it exists — ends every session it has open. A stolen session
/// must not outlive the password reset that was the response to the theft.
#[test]
fn changing_an_account_ends_its_sessions() {
    let changed_password = crate::passwd::hash("a-different-password").unwrap();
    let mutations: Vec<(&str, String)> = vec![
        ("password", local_config(&changed_password, "")),
        (
            "second factor",
            local_config(hash(), "totp = \"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\"\n"),
        ),
        (
            "group",
            local_config(hash(), "").replace("group = \"ops\"", "group = \"viewers\""),
        ),
        (
            "group permission",
            local_config(hash(), "").replacen(
                "permission = \"read-write\"",
                "permission = \"read-only\"",
                1,
            ),
        ),
        (
            "deletion",
            "[system]\nhostname = \"fw\"\n\
             [[system.group]]\nname = \"ops\"\npermission = \"read-write\"\n"
                .into(),
        ),
    ];
    for (what, after) in mutations {
        let st = bench(&local_config(hash(), ""), Arc::new(ConfiguredServers));
        let token = token_of(&sign_in(&st, "vera", PASSWORD, "").unwrap());
        assert!(resolve_caller(&st, &token).is_some());
        rewrite(&st, &after);
        assert!(
            resolve_caller(&st, &token).is_none(),
            "changing the account's {what} left its session open"
        );
        // …and the commit-time reconciliation removes it from disk too.
        sync_user_tokens(&st).unwrap();
        assert_eq!(
            std::fs::read_dir(&st.tokens_dir).unwrap().count(),
            0,
            "changing the account's {what} left its session on disk"
        );
    }
}

/// A commit that changes something else entirely — the hostname, a rule — logs
/// nobody out.
#[test]
fn an_unrelated_commit_keeps_sessions() {
    let st = bench(&local_config(hash(), ""), Arc::new(ConfiguredServers));
    let token = token_of(&sign_in(&st, "vera", PASSWORD, "").unwrap());
    rewrite(
        &st,
        &local_config(hash(), "").replace("hostname = \"fw\"", "hostname = \"fw2\""),
    );
    sync_user_tokens(&st).unwrap();
    assert!(resolve_caller(&st, &token).is_some());
}

/// The token directory holds digests, never the bearer itself: a backup of
/// `/var/lib/sentinel`, or a read of it, is not a way in.
#[test]
fn tokens_are_stored_hashed() {
    let st = bench(&local_config(hash(), ""), Arc::new(ConfiguredServers));
    let token = token_of(&sign_in(&st, "vera", PASSWORD, "").unwrap());
    for entry in std::fs::read_dir(&st.tokens_dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let contents = std::fs::read_to_string(entry.path()).unwrap();
        assert!(!name.contains(&token) && !contents.contains(&token));
        let mode =
            std::os::unix::fs::PermissionsExt::mode(&entry.metadata().unwrap().permissions());
        assert_eq!(mode & 0o077, 0, "a session file is readable by others");
    }
}

/// The per-account token files of the previous scheme were bearer secrets in
/// the clear that never expired. They are withdrawn, not honoured.
#[test]
fn per_account_token_files_from_before_are_withdrawn() {
    let st = bench(&local_config(hash(), ""), Arc::new(ConfiguredServers));
    std::fs::create_dir_all(&st.tokens_dir).unwrap();
    std::fs::write(st.tokens_dir.join("vera"), "legacy-clear-token\n").unwrap();
    assert!(resolve_caller(&st, "legacy-clear-token").is_none());
    sync_user_tokens(&st).unwrap();
    assert!(!st.tokens_dir.join("vera").exists());
}

// ---- throttling (#18) ------------------------------------------------------

/// Guesses fired in parallel from one address used to all pass the lockout
/// check before the first of them was counted. At most the threshold may
/// reach a password check; the rest are refused up front.
#[tokio::test]
async fn parallel_guesses_from_one_address_are_bounded() {
    let ip: std::net::IpAddr = "203.0.113.60".parse().unwrap();
    ip_throttle().forget(ip);
    let directory = FakeDirectory::new(None);
    let st = bench(&directory_config(Some("viewers")), directory.clone());
    const GUESSES: usize = 40;
    let mut handles = Vec::new();
    for n in 0..GUESSES {
        let st = st.clone();
        handles.push(tokio::spawn(async move {
            let mut req = Request::builder()
                .method("POST")
                .uri("/api/v1/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"username":"guess{n}","password":"wrong-{n}"}}"#
                )))
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 60], 4000))));
            router(st).oneshot(req).await.unwrap().status()
        }));
    }
    let mut throttled = 0;
    for h in handles {
        if h.await.unwrap() == StatusCode::TOO_MANY_REQUESTS {
            throttled += 1;
        }
    }
    let checked = directory.calls.load(Ordering::SeqCst);
    ip_throttle().forget(ip);
    assert!(
        checked <= IP_MAX_FAILURES as usize,
        "{checked} passwords were checked for one address (limit {IP_MAX_FAILURES})"
    );
    assert_eq!(throttled + checked, GUESSES);
}

/// A full table must not make room by forgetting a lockout — that was a way to
/// unlock yourself by spraying from other addresses. When nothing but locks
/// is left, a new address is refused rather than one of them released.
#[test]
fn a_locked_address_survives_eviction_pressure() {
    let throttle = IpThrottle::new(4);
    let locked: std::net::IpAddr = "198.51.100.1".parse().unwrap();
    for _ in 0..IP_MAX_FAILURES {
        throttle.reserve(locked).unwrap();
    }
    for n in 2..40u8 {
        assert_eq!(
            throttle.reserve(std::net::IpAddr::from([198, 51, 100, n])),
            Ok(())
        );
    }
    assert!(
        matches!(throttle.reserve(locked), Err(IpRefusal::Locked(_))),
        "eviction released a locked address"
    );

    // Fill the table with locks: the next newcomer is turned away.
    let throttle = IpThrottle::new(2);
    for n in 1..=2u8 {
        for _ in 0..IP_MAX_FAILURES {
            throttle
                .reserve(std::net::IpAddr::from([198, 51, 100, n]))
                .unwrap();
        }
    }
    assert_eq!(
        throttle.reserve("198.51.100.3".parse().unwrap()),
        Err(IpRefusal::Full)
    );
    assert!(matches!(
        throttle.reserve("198.51.100.1".parse().unwrap()),
        Err(IpRefusal::Locked(_))
    ));
}

// ---- uniform refusals (LOW) ------------------------------------------------

/// Whatever was wrong — the account, the password, a missing or wrong code, an
/// account with no password — the answer is the same status and the same
/// words, so the answer says nothing about which part was right.
#[test]
fn every_refusal_reads_the_same() {
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let config = local_config(
        hash(),
        &format!("totp = \"{SECRET}\"\n[[system.login]]\nusername = \"nopass\"\ngroup = \"ops\"\n"),
    );
    let st = bench(&config, Arc::new(ConfiguredServers));
    let refusal = |user: &str, password: &str, code: &str| {
        let e = sign_in(&st, user, password, code).expect_err("this sign-in must be refused");
        (e.status, e.message)
    };
    let expected = refusal("nobody", "whatever-it-is", "");
    assert_eq!(expected.0, StatusCode::UNAUTHORIZED);
    let cases = [
        ("wrong password", refusal("vera", "not-the-password", "")),
        ("missing code", refusal("vera", PASSWORD, "")),
        ("wrong code", refusal("vera", PASSWORD, "000001")),
        ("malformed code", refusal("vera", PASSWORD, "12")),
        ("no password set", refusal("nopass", "whatever-it-is", "")),
    ];
    for (what, got) in cases {
        assert_eq!(got, expected, "a {what} answered differently");
    }

    // A directory's refusal reads the same as a local one.
    let st = bench(&directory_config(Some("viewers")), FakeDirectory::new(None));
    let e = sign_in(&st, "dirk", "wrong", "").expect_err("refused");
    assert_eq!((e.status, e.message), expected);
}

/// The right password with the right code still gets in, sent together in the
/// one request the console now always makes.
#[test]
fn password_and_code_in_one_request_sign_in() {
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let st = bench(
        &local_config(hash(), &format!("totp = \"{SECRET}\"\n")),
        Arc::new(ConfiguredServers),
    );
    let code = crate::aaa::totp_at(SECRET, crate::aaa::unix_now()).unwrap();
    let session = sign_in(&st, "vera", PASSWORD, &code).expect("both factors were refused");
    assert!(resolve_caller(&st, &token_of(&session)).is_some());
}
