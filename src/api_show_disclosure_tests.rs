// Included only inside api::tests. No production diagnostic/test adapter.

fn failed_show(stderr: &[u8], raw_status: i32) -> std::process::Output {
    use std::os::unix::process::ExitStatusExt;
    std::process::Output {
        status: std::process::ExitStatus::from_raw(raw_status),
        // A partially rendered failed command is not a successful observation.
        stdout: b"partial-private-output-do-not-release".to_vec(),
        stderr: stderr.to_vec(),
    }
}

#[test]
fn failed_show_withholds_unknown_archived_machine_secrets_from_both_account_roles() {
    let marker = "unknown-historical-machine-secret-not-in-active-config";
    let (state, viewer, operator) = secret_state();
    assert!(
        redact::every_secret_value(&state.appliance().unwrap())
            .iter()
            .all(|value| value != marker)
    );
    let malformed =
        Appliance::from_toml(&format!("[system.config-sync]\nsecret = \"{marker}")).unwrap_err();
    let diagnostic = format!("Error: {malformed:#}");
    assert!(diagnostic.contains(marker));
    let output = failed_show(diagnostic.as_bytes(), 7 << 8);
    for (token, expected) in [
        (viewer, Disclosure::NoSecrets),
        (operator, Disclosure::NoMachineCredential),
    ] {
        let caller = resolve_caller(&state, &token).unwrap();
        let disclosure = show_disclosure(&caller, &axum::http::HeaderMap::new());
        assert_eq!(disclosure, expected);
        let error = show_failure(disclosure, &output);
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.contains("collector exit 7"));
        assert!(error.message.contains("view path"));
        assert!(!error.message.contains(marker));
        assert!(!error.message.contains("TOML parse error"));
        assert!(!error.message.contains("partial-private-output"));
    }
}

#[test]
fn failed_show_preserves_full_machine_diagnostics_only_without_effective_narrowing() {
    let marker = "unknown-archive-secret-full-machine-control";
    let output = failed_show(marker.as_bytes(), 1 << 8);
    let caller = Caller {
        user: None,
        permission: crate::config::Permission::ReadWrite,
    };
    let mut headers = axum::http::HeaderMap::new();
    assert_eq!(show_disclosure(&caller, &headers), Disclosure::Full);
    let error = show_failure(show_disclosure(&caller, &headers), &output);
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.message, marker);
    for level in ["secrets", "machine-credential", "unknown-level"] {
        headers.insert(REDACT_HEADER, level.parse().unwrap());
        let disclosure = show_disclosure(&caller, &headers);
        assert_ne!(disclosure, Disclosure::Full);
        let error = show_failure(disclosure, &output);
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(!error.message.contains(marker));
        assert!(error.message.contains("collector exit 1"));
    }
    // Even a spelling resembling a full-view request cannot widen an account.
    headers.insert(REDACT_HEADER, "full".parse().unwrap());
    let account = Caller {
        user: Some("operator".into()),
        permission: crate::config::Permission::ReadWrite,
    };
    assert_eq!(show_disclosure(&account, &headers), Disclosure::NoSecrets);
    assert!(
        !show_failure(show_disclosure(&account, &headers), &output)
            .message
            .contains(marker)
    );
}

#[test]
fn failed_show_empty_non_utf8_and_signal_diagnostics_keep_safe_failure_status() {
    for disclosure in [Disclosure::NoSecrets, Disclosure::NoMachineCredential] {
        for stderr in [b"".as_slice(), b" \n\t", b"\xffprivate-unknown-secret\xfe"] {
            let error = show_failure(disclosure, &failed_show(stderr, 1 << 8));
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert!(error.message.contains("collector exit 1"));
            assert!(!error.message.contains("private-unknown-secret"));
            assert!(!error.message.contains('\u{fffd}'));
        }
        let error = show_failure(disclosure, &failed_show(b"private", libc::SIGKILL));
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.contains("collector exit terminated"));
        assert!(!error.message.contains("private"));
    }
    assert_eq!(
        show_failure(Disclosure::Full, &failed_show(b" \n\t", 1 << 8)).message,
        "show failed"
    );
    assert_eq!(
        show_failure(
            Disclosure::Full,
            &failed_show(b"\xfffull-diagnostic", 1 << 8)
        )
        .message,
        "\u{fffd}full-diagnostic"
    );
}

#[tokio::test]
async fn failed_show_json_response_retains_http_400_without_raw_output() {
    let response = show_failure(
        Disclosure::NoSecrets,
        &failed_show(b"protected-source-snippet", 23 << 8),
    )
    .into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let body: Value = serde_json::from_str(&body_string(response).await).unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("collector exit 23")
    );
    assert!(!body.to_string().contains("protected-source-snippet"));
}

#[tokio::test]
async fn stack_show_does_not_forward_a_real_pinned_https_peers_private_error_body() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    const UNKNOWN: &str = "unknown-private-remote-archive-error-secret";
    let remote_path = seed("peer-private-error");
    let directory = remote_path.parent().unwrap();
    let cert = directory.join("cert.pem");
    let key = directory.join("key.pem");
    system::ensure_self_signed_cert(&cert, &key, "peer", &["127.0.0.1".into()]).unwrap();
    let pin = system::cert_pubkey_pin(&cert).unwrap();
    install_crypto_provider();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
        .await
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let observed = Arc::new(AtomicUsize::new(0));
    let remote_observed = Arc::clone(&observed);
    // This independent peer deliberately emits an old, unsafe parser error.
    // Its error must not become safe merely because the caller asked it nicely.
    let remote = Router::new().route(
        "/api/v1/show/system/commit/0",
        axum::routing::get(move |headers: axum::http::HeaderMap| {
            let observed = Arc::clone(&remote_observed);
            async move {
                assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
                assert_eq!(headers[REDACT_HEADER], "secrets");
                observed.fetch_add(1, Ordering::SeqCst);
                (StatusCode::BAD_REQUEST, Json(json!({"error": UNKNOWN})))
            }
        }),
    );
    let server = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .serve(remote.into_make_service())
            .await
            .unwrap();
    });
    let (state, viewer, operator) = secret_state();
    let mut appliance = state.appliance().unwrap();
    assert!(
        !redact::every_secret_value(&appliance)
            .iter()
            .any(|value| value == UNKNOWN)
    );
    appliance.system.config_sync.peers = vec![address.to_string()];
    appliance.system.config_sync.secret = Some(TOKEN.into());
    appliance.system.config_sync.peer_fingerprint = Some(pin);
    session::persist_appliance(&appliance, &state.config_path, false).unwrap();
    let app = router(state);
    for token in [viewer.as_str(), operator.as_str(), TOKEN] {
        let response = app
            .clone()
            .oneshot(get(
                &format!("/api/v1/stack/{address}/show/system/commit/0"),
                Some(token),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_string(response).await;
        assert!(body.contains("HTTP 400"), "{body}");
        assert!(!body.contains(UNKNOWN), "{body}");
        assert!(!body.contains(TOKEN), "{body}");
    }
    assert_eq!(observed.load(Ordering::SeqCst), 3);
    server.abort();
}
