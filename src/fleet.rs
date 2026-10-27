//! Optional outbound fleet hook. TLS identity and Ed25519 command authority are
//! independent. Fleet changes enter the same durable commit-confirm engine as
//! local management; an HTTP response is never an implicit confirmation.
use crate::{
    config::{Appliance, Fleet},
    net::ApplyMode,
    repl::Apply,
    safe_apply, system,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::{digest, signature};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const RUNTIME: &str = "/run/sentinel/fleet.json";
const TIMER_DROPIN: &str = "/run/systemd/system/sentinel-fleet.timer.d/interval.conf";
const DOMAIN: &[u8] = b"Velstra Sentinel Fleet command v1\0";
const LIMIT: usize = 2_097_152;
/// Where fleet credentials are provisioned. A `file:` enrollment token must be a
/// file directly in here: the token is sent to whatever `controller-url` says,
/// so a reference that could name any root-owned 0600 file (an SSH host key, the
/// config-sync secret, `/etc/shadow`'s neighbours) would let anyone able to set
/// these two fields post that file to a server of their choosing.
const CREDENTIAL_DIR: &str = "/var/lib/sentinel/fleet";

pub fn validate(f: &Fleet) -> Result<()> {
    let url: axum::http::Uri = f
        .controller_url
        .parse()
        .context("fleet controller-url must be HTTPS")?;
    ensure!(
        !f.controller_url.contains('#')
            && url.scheme_str() == Some("https")
            && url.authority().is_some_and(|a| !a.host().is_empty()
                && !a.as_str().contains('@')
                && a.port_u16() != Some(0))
            && url.query().is_none(),
        "fleet controller-url must be an HTTPS base URL without userinfo or a query"
    );
    ensure!(
        !f.node_id.is_empty()
            && f.node_id.len() <= 128
            && f.node_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "fleet node-id must contain 1–128 letters, digits, dots, underscores or hyphens"
    );
    for (field, path) in [
        ("ca-certificate", &f.ca_certificate),
        ("client-certificate", &f.client_certificate),
        ("client-key", &f.client_key),
    ] {
        ensure!(
            Path::new(path).is_absolute() && !path.chars().any(char::is_control),
            "fleet {field} must be an absolute file path"
        );
    }
    ensure!(
        f.enrollment_token.len() >= 16
            && f.enrollment_token.len() <= 4096
            && !f.enrollment_token.chars().any(char::is_control),
        "fleet enrollment-token must contain 16–4096 characters without control characters"
    );
    if let Some(path) = f.enrollment_token.strip_prefix("file:") {
        token_file_name(path)?;
    }
    ensure!(
        STANDARD
            .decode(&f.signing_key)
            .is_ok_and(|key| key.len() == 32),
        "fleet signing-key must be a base64 Ed25519 public key (32 bytes)"
    );
    ensure!(
        (1..=300).contains(&f.poll_interval.unwrap_or(5)),
        "fleet poll-interval must be 1–300 seconds"
    );
    Ok(())
}

/// Pure desired-state rendering; no network operation is on the apply path.
pub fn reconcile(a: &Appliance, mode: ApplyMode) -> Result<()> {
    let desired = serde_json::to_string(&a.fleet)?;
    let changed = system::read_owned_file(Path::new(RUNTIME))?.as_deref() != Some(&desired);
    if changed {
        system::install_ha_secret(Path::new(RUNTIME), &desired)?;
    }
    let interval = format!(
        "[Timer]\nOnUnitInactiveSec=\nOnActiveSec=1s\nOnUnitInactiveSec={}s\n",
        a.fleet.as_ref().and_then(|f| f.poll_interval).unwrap_or(5)
    );
    let timer_changed =
        system::read_owned_file(Path::new(TIMER_DROPIN))?.as_deref() != Some(&interval);
    if timer_changed {
        system::install_file(Path::new(TIMER_DROPIN), &interval)?;
    }
    if mode == ApplyMode::Live {
        if timer_changed {
            system::daemon_reload()?;
        }
        if a.fleet.is_some() {
            if changed || timer_changed {
                system::service_restart("sentinel-fleet.timer")?;
            } else {
                system::service_start("sentinel-fleet.timer")?;
            }
        } else {
            system::service_stop("sentinel-fleet.timer")?;
            system::service_stop("sentinel-fleet.service")?;
        }
    }
    Ok(())
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct State {
    trust: String,
    sequence: u64,
    command_digest: String,
    result: Value,
    telemetry_requested: bool,
}
fn state_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        ".{}.fleet.json",
        path.file_name().unwrap_or_default().to_string_lossy()
    ))
}
fn hash(bytes: &[u8]) -> String {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn trust(f: &Fleet) -> String {
    hash(format!("{}\0{}\0{}", f.controller_url, f.node_id, f.signing_key).as_bytes())
}
fn load_state(path: &Path, f: &Fleet) -> Result<State> {
    let mut state: State = match system::read_owned_file(&state_path(path))? {
        Some(text) => serde_json::from_str(&text)
            .context("fleet state is corrupt; refusing to reset replay protection")?,
        None => State::default(),
    };
    if state.trust != trust(f) {
        state = State {
            trust: trust(f),
            ..Default::default()
        };
    }
    Ok(state)
}
fn save_state(path: &Path, state: &State) -> Result<()> {
    system::install_ha_secret(&state_path(path), &serde_json::to_string(state)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    command: Option<Envelope>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: String,
    signature: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FleetCommand {
    sequence: u64,
    operation: Operation,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum Operation {
    Telemetry,
    Apply {
        expected_revision: String,
        toml: String,
    },
    Confirm {
        id: String,
        revision: String,
    },
    Revert {
        id: String,
    },
}
fn signing_message(node: &str, nonce: &str, payload: &[u8]) -> Vec<u8> {
    [
        DOMAIN,
        node.as_bytes(),
        b"\0",
        nonce.as_bytes(),
        b"\0",
        payload,
    ]
    .concat()
}
fn verify(f: &Fleet, nonce: &str, envelope: &Envelope) -> Result<(FleetCommand, String)> {
    ensure!(
        envelope.payload.len() <= LIMIT,
        "fleet signed command exceeds receive limit"
    );
    let payload = STANDARD
        .decode(&envelope.payload)
        .context("invalid fleet payload encoding")?;
    let sig = STANDARD
        .decode(&envelope.signature)
        .context("invalid fleet signature encoding")?;
    let key = STANDARD.decode(&f.signing_key)?;
    signature::UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(&signing_message(&f.node_id, nonce, &payload), &sig)
        .map_err(|_| {
            anyhow::anyhow!("fleet command signature/identity/challenge verification failed")
        })?;
    let cmd: FleetCommand =
        serde_json::from_slice(&payload).context("invalid signed fleet command")?;
    ensure!(cmd.sequence > 0, "fleet sequence must be nonzero");
    Ok((cmd, hash(&payload)))
}

/// Never retain the global apply lock across a controller request. An offline
/// fleet controller must not block local configuration or standalone forwarding.
pub fn poll(path: &Path, act: &Apply) -> Result<()> {
    let a = Appliance::load(path)?;
    let Some(f) = a.fleet.as_ref() else {
        return Ok(());
    };
    validate(f)?;
    if act.enabled && !runtime_matches(f)? {
        return Ok(());
    }
    let state = load_state(path, f)?;
    let mut random = [0u8; 32];
    getrandom::getrandom(&mut random)
        .map_err(|_| anyhow::anyhow!("fleet challenge randomness unavailable"))?;
    let nonce = hash(&random);
    let request = json!({"protocol":1,"node":f.node_id,"nonce":nonce,"revision":crate::ha::revision(&a)?,"sequence":state.sequence,"result":state.result,"transaction":safe_apply::status(path)?,"telemetry":if state.telemetry_requested {crate::telemetry::fleet_snapshot(f.flow_telemetry)} else {Value::Null}});
    let reply: Reply = serde_json::from_str(&request_controller(f, &request)?)
        .context("invalid fleet check-in response")?;
    if let Some(envelope) = reply.command {
        let (command, digest) = verify(f, &nonce, &envelope)?;
        execute(path, f, command, &digest, act)?;
    } else if state.telemetry_requested {
        acknowledge_telemetry(path, f, state.sequence, act)?;
    }
    Ok(())
}
fn acknowledge_telemetry(path: &Path, f: &Fleet, sequence: u64, act: &Apply) -> Result<()> {
    let _lock = system::apply_lock()?;
    let _file = system::lock_config_at(&path.with_extension("transaction.lock"))?;
    let current_config = Appliance::load(path)?;
    ensure!(
        current_config.fleet.as_ref() == Some(f) && (!act.enabled || runtime_matches(f)?),
        "fleet enrollment changed while the request was in flight"
    );
    let mut current = load_state(path, f)?;
    if current.sequence == sequence {
        current.telemetry_requested = false;
        save_state(path, &current)?;
    }
    Ok(())
}

fn runtime_matches(f: &Fleet) -> Result<bool> {
    let runtime: Option<Fleet> = serde_json::from_str(
        &system::read_owned_file(Path::new(RUNTIME))?.context("fleet runtime intent is absent")?,
    )?;
    Ok(runtime.as_ref() == Some(f))
}
fn execute(path: &Path, f: &Fleet, command: FleetCommand, digest: &str, act: &Apply) -> Result<()> {
    let _lock = system::apply_lock()?;
    let _file = system::lock_config_at(&path.with_extension("transaction.lock"))?;
    let a = Appliance::load(path)?;
    ensure!(
        a.fleet.as_ref() == Some(f) && (!act.enabled || runtime_matches(f)?),
        "fleet enrollment changed while the request was in flight"
    );
    let mut state = load_state(path, f)?;
    if command.sequence == state.sequence && digest == state.command_digest {
        return Ok(());
    }
    ensure!(
        command.sequence > state.sequence,
        "fleet command replay or conflicting sequence"
    );
    state.sequence = command.sequence;
    state.command_digest = digest.into();
    state.result = json!({"state":"processing"});
    // Consume the sequence durably BEFORE side effects. A crash never resets the
    // high-water mark; the controller observes transaction status on reconnect.
    save_state(path, &state)?;
    let result = (|| -> Result<Value> {
        match command.operation {
            Operation::Telemetry => {
                state.telemetry_requested = true;
                Ok(json!({"telemetry":"next-check-in"}))
            }
            Operation::Apply {
                expected_revision,
                toml,
            } => {
                ensure!(
                    crate::ha::revision(&a)? == expected_revision,
                    "fleet configuration baseline changed"
                );
                let next = Appliance::from_toml(&toml)
                    .map_err(|_| anyhow::anyhow!("fleet configuration failed schema validation"))?;
                refuse_local_only_changes(&a, &next)?;
                safe_apply::begin(
                    path,
                    &next,
                    act,
                    a.services.web.confirm_timeout.unwrap_or(60),
                )
            }
            Operation::Confirm { id, revision } => {
                ensure!(
                    crate::ha::revision(&a)? == revision,
                    "fleet confirmation revision mismatch"
                );
                safe_apply::confirm(path, &id, act)
            }
            Operation::Revert { id } => Ok(json!({"reverted":safe_apply::revert(path,&id,act)?})),
        }
    })();
    state.result = match &result {
        Ok(value) => json!({"state":"accepted","details":value}),
        Err(_) => json!({"state":"refused"}),
    };
    save_state(path, &state)?;
    result.map(|_| ())
}

/// The settings a fleet controller may never change: who can manage this box,
/// how, and whom it trusts. Each is a trust anchor in its own right — a
/// controller able to rewrite any of them could make itself (or anyone) a
/// permanent local administrator, swap the key that vouches for OS images, or
/// re-pair the box with a peer of its choosing, and then the commit-confirm
/// window would be the controller confirming its own takeover. Changing them is
/// a local management act, exactly like re-enrolling fleet itself.
///
/// In the set:
/// * `fleet` — enrollment, the controller URL and the command-signing key.
/// * `system.login` — accounts, SSH authorized keys, password hashes, TOTP.
/// * `system.group` — what each account may do through the management API.
/// * `system.aaa` — RADIUS/LDAP/TACACS servers and their secrets decide who
///   logs in; a controller pointing them at its own server is a login for
///   anyone it likes.
/// * `update` — channel URLs, their pinned public keys and subscription keys.
///   The channel key also verifies local images (`sentinel update <image>`).
/// * `system.ha`, `system.ha-witness`, `system.config-sync`,
///   `system.conntrack-sync` — the pairing identity, witness secret, the
///   config-sync peers/secret/pinned fingerprint and the state-sync endpoints.
///   Config-sync pushes the whole configuration to its peers, so whoever
///   chooses the peer receives every secret; the HA receiver already keeps its
///   own copies of these (`merge_synced_config`), this keeps them local on the
///   fleet road too.
/// * `services.ssh`, `services.web`, `system.console` — the ways the local
///   operator reaches the box (listen addresses, ports, TLS material, password
///   authentication, the serial console). A controller that can close them can
///   lock the operator out of the one place these settings can be repaired.
///
/// Deliberately NOT in the set — the policy a fleet exists to manage: rules,
/// zones, NAT, interfaces, routing, VPN tunnels (their keys authorize data
/// traffic, not management), PKI definitions (key material is minted on the box,
/// and the console's certificate is pinned through `services.web`), services
/// such as DNS/DHCP/syslog/alerts, metrics and sysctl. A policy change that cuts
/// the controller's own reachability is what the commit-confirm watchdog is for.
fn local_only_sections(a: &Appliance) -> Result<[(&'static str, Value); 12]> {
    use serde_json::to_value;
    Ok([
        ("fleet", to_value(&a.fleet)?),
        ("system.login", to_value(&a.system.logins)?),
        ("system.group", to_value(&a.system.groups)?),
        ("system.aaa", to_value(&a.system.aaa)?),
        ("update", to_value(&a.update)?),
        ("system.ha", to_value(&a.system.ha)?),
        ("system.ha-witness", to_value(&a.system.ha_witness)?),
        ("system.config-sync", to_value(&a.system.config_sync)?),
        ("system.conntrack-sync", to_value(&a.system.conntrack_sync)?),
        ("services.ssh", to_value(&a.services.ssh)?),
        ("services.web", to_value(&a.services.web)?),
        ("system.console", to_value(&a.system.console)?),
    ])
}

/// Refuse a fleet revision that differs from the running one anywhere in
/// [`local_only_sections`], naming every section it would have changed so the
/// controller's operator knows what to take out of the document.
fn refuse_local_only_changes(current: &Appliance, next: &Appliance) -> Result<()> {
    let changed: Vec<&str> = local_only_sections(current)?
        .into_iter()
        .zip(local_only_sections(next)?)
        .filter(|((_, before), (_, after))| before != after)
        .map(|((name, _), _)| name)
        .collect();
    ensure!(
        changed.is_empty(),
        "fleet cannot change local-only trust settings ({}); change them on the appliance itself",
        changed.join(", ")
    );
    Ok(())
}

/// The file name a `file:` enrollment-token reference names inside
/// [`CREDENTIAL_DIR`], or a refusal for anything else: another directory, a
/// subdirectory, a `..` climb.
fn token_file_name(path: &str) -> Result<&str> {
    let name = path
        .strip_prefix(CREDENTIAL_DIR)
        .and_then(|rest| rest.strip_prefix('/'))
        .filter(|name| {
            !name.is_empty()
                && !matches!(*name, "." | "..")
                && !name.contains('/')
                && !name.chars().any(char::is_control)
        });
    name.with_context(|| {
        format!("fleet enrollment-token file must be a file directly in {CREDENTIAL_DIR}/")
    })
}

/// Read a credential file `name` from `dir` without following a link at
/// either step. The directory is opened `O_NOFOLLOW` and must belong to this
/// process and be writable by nobody else, so the entry cannot be swapped
/// underneath us; the file is then opened relative to that handle, again
/// `O_NOFOLLOW`, so a symlink planted as the token cannot point back out.
fn private_credential_in(dir: &Path, name: &str) -> Result<String> {
    use std::{
        ffi::CString,
        io::Read,
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::{AsRawFd, FromRawFd},
        },
    };
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)
        .with_context(|| format!("opening fleet credential directory {}", dir.display()))?;
    let meta = directory.metadata()?;
    ensure!(
        meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o022 == 0,
        "fleet credential directory {} must be owned by this process and writable by nobody else",
        dir.display()
    );
    let c_name = CString::new(Path::new(name).as_os_str().as_bytes())?;
    // SAFETY: a valid directory descriptor and NUL-terminated name; the
    // returned descriptor is owned by the File constructed from it.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    ensure!(
        fd >= 0,
        "opening fleet credential {name}: {}",
        std::io::Error::last_os_error()
    );
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0
            && meta.len() <= 4096,
        "fleet credential file must be private, owned by this process and at most 4096 bytes"
    );
    let mut text = String::new();
    file.take(4097).read_to_string(&mut text)?;
    ensure!(
        text.len() <= 4096,
        "fleet credential file exceeds receive limit"
    );
    Ok(text.trim().into())
}

/// The check-in request, credential-free on its command line (the bearer token
/// and the body travel over stdin as curl config). [`system::curl_command`]
/// supplies `--disable` as the first option and an empty environment, so neither
/// `~/.curlrc` nor an ambient proxy/key-log/CA variable can weaken TLS, add
/// proxy credentials or redirects, or log the token.
fn check_in_command(f: &Fleet) -> Command {
    let mut command = system::curl_command();
    command.args([
        "--silent",
        "--show-error",
        "--fail",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "--max-time",
        "10",
        "--connect-timeout",
        "5",
        "--max-filesize",
        "2097152",
        "--cacert",
        &f.ca_certificate,
        "--cert",
        &f.client_certificate,
        "--key",
        &f.client_key,
        "--request",
        "POST",
        "--header",
        "Content-Type: application/json",
        "--config",
        "-",
        &format!(
            "{}/api/v1/sentinel/check-in",
            f.controller_url.trim_end_matches('/')
        ),
    ]);
    command
}

fn config_string(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    )
}
fn request_controller(f: &Fleet, body: &Value) -> Result<String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::metadata(&f.client_key).context("reading fleet client key metadata")?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o077 == 0,
        "fleet client-key must be an owned private regular file (0600)"
    );
    let token = if let Some(path) = f.enrollment_token.strip_prefix("file:") {
        private_credential_in(Path::new(CREDENTIAL_DIR), token_file_name(path)?)?
    } else {
        f.enrollment_token.clone()
    };
    ensure!(
        token.len() >= 16 && token.len() <= 4096 && !token.chars().any(char::is_control),
        "invalid fleet enrollment credential"
    );
    let mut child = check_in_command(f)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("starting fleet HTTPS request")?;
    let config = format!(
        "header = {}\ndata-binary = {}\n",
        config_string(&format!("Authorization: Bearer {token}")),
        config_string(&serde_json::to_string(body)?)
    );
    if let Err(error) = child
        .stdin
        .take()
        .context("fleet request stdin")?
        .write_all(config.as_bytes())
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error.into());
    }
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success(),
        "fleet controller HTTPS request failed ({})",
        output.status
    );
    ensure!(
        output.stdout.len() <= LIMIT,
        "fleet response exceeds receive limit"
    );
    String::from_utf8(output.stdout).context("fleet response is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;
    fn identity() -> Fleet {
        Fleet {
            controller_url: "https://fleet.example".into(),
            node_id: "edge-a".into(),
            enrollment_token: "test-enrollment-credential".into(),
            ca_certificate: "/etc/fleet/ca.pem".into(),
            client_certificate: "/etc/fleet/client.pem".into(),
            client_key: "/etc/fleet/client.key".into(),
            signing_key: STANDARD.encode([0u8; 32]),
            poll_interval: Some(5),
            flow_telemetry: false,
        }
    }
    fn key() -> signature::Ed25519KeyPair {
        signature::Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap()
    }
    fn fixture() -> (PathBuf, Appliance) {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).unwrap();
        let dir = std::env::temp_dir().join(format!("sentinel-fleet-{}", hash(&random)));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("appliance.toml");
        let mut a = Appliance::from_toml("[system]\nhostname=\"working\"\n").unwrap();
        let mut f = identity();
        f.signing_key = STANDARD.encode(key().public_key().as_ref());
        a.fleet = Some(f);
        crate::session::persist_appliance(&a, &path, false).unwrap();
        (path, a)
    }
    fn deliver(path: &Path, f: &Fleet, sequence: u64, operation: Operation) -> Result<()> {
        let bytes = serde_json::to_vec(&FleetCommand {
            sequence,
            operation,
        })?;
        let envelope = Envelope {
            payload: STANDARD.encode(&bytes),
            signature: STANDARD.encode(
                key()
                    .sign(&signing_message(&f.node_id, "challenge", &bytes))
                    .as_ref(),
            ),
        };
        let (command, digest) = verify(f, "challenge", &envelope)?;
        execute(path, f, command, &digest, &Apply::off())
    }
    #[test]
    fn standalone_has_no_fleet_network_dependency() {
        let (path, mut a) = fixture();
        a.fleet = None;
        crate::session::persist_appliance(&a, &path, false).unwrap();
        poll(&path, &Apply::off()).unwrap();
        assert!(!state_path(&path).exists());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    #[test]
    fn fleet_validation_rejects_unsafe_transport_and_partial_identity() {
        validate(&identity()).unwrap();
        for url in [
            "http://fleet.example",
            "https://user:password@fleet.example",
            "https://fleet.example/?token=oops",
            "https://fleet.example/#fragment",
            "",
        ] {
            let mut f = identity();
            f.controller_url = url.into();
            assert!(validate(&f).is_err(), "{url}");
        }
        for n in [0, 301] {
            let mut f = identity();
            f.poll_interval = Some(n);
            assert!(validate(&f).is_err());
        }
        let mut f = identity();
        f.client_key = "relative.key".into();
        assert!(validate(&f).is_err());
        f = identity();
        f.signing_key = STANDARD.encode([1u8; 31]);
        assert!(validate(&f).is_err());
        f = identity();
        f.enrollment_token = "bad\ncredentialxxxxxxxx".into();
        assert!(validate(&f).is_err());
        assert!(!format!("{:?}", identity()).contains("test-enrollment-credential"));
    }
    #[test]
    fn signatures_bind_the_target_challenge_payload_and_signing_authority() {
        let mut f = identity();
        f.signing_key = STANDARD.encode(key().public_key().as_ref());
        let bytes = serde_json::to_vec(&FleetCommand {
            sequence: 1,
            operation: Operation::Telemetry,
        })
        .unwrap();
        let mut e = Envelope {
            payload: STANDARD.encode(&bytes),
            signature: STANDARD.encode(
                key()
                    .sign(&signing_message(&f.node_id, "nonce", &bytes))
                    .as_ref(),
            ),
        };
        assert!(verify(&f, "nonce", &e).is_ok());
        assert!(verify(&f, "other-nonce", &e).is_err());
        let mut other = f.clone();
        other.node_id = "edge-b".into();
        assert!(verify(&other, "nonce", &e).is_err());
        other = f.clone();
        other.signing_key = STANDARD.encode([7u8; 32]);
        assert!(verify(&other, "nonce", &e).is_err());
        e.payload = STANDARD.encode(b"{\"sequence\":2}");
        assert!(verify(&f, "nonce", &e).is_err());
    }
    #[test]
    fn a_signed_revision_requires_explicit_confirmation_and_duplicate_delivery_is_idempotent() {
        use std::os::unix::fs::PermissionsExt;
        let (path, a) = fixture();
        let f = a.fleet.as_ref().unwrap();
        let mut next = a.clone();
        next.system.hostname = "fleet-applied".into();
        let operation = || Operation::Apply {
            expected_revision: crate::ha::revision(&a).unwrap(),
            toml: next.to_toml().unwrap(),
        };
        deliver(&path, f, 1, operation()).unwrap();
        let pending = safe_apply::status(&path).unwrap()["pending"].clone();
        assert!(pending["ready"].as_bool().unwrap());
        deliver(&path, f, 1, operation()).unwrap();
        assert_eq!(safe_apply::status(&path).unwrap()["pending"], pending);
        assert_eq!(
            std::fs::metadata(state_path(&path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(deliver(&path, f, 1, Operation::Telemetry).is_err());
        assert!(
            deliver(
                &path,
                f,
                2,
                Operation::Confirm {
                    id: pending["id"].as_str().unwrap().into(),
                    revision: crate::ha::revision(&a).unwrap()
                }
            )
            .is_err()
        );
        assert!(safe_apply::status(&path).unwrap()["pending"].is_object());
        deliver(
            &path,
            f,
            3,
            Operation::Confirm {
                id: pending["id"].as_str().unwrap().into(),
                revision: crate::ha::revision(&next).unwrap(),
            },
        )
        .unwrap();
        assert!(safe_apply::status(&path).unwrap()["pending"].is_null());
        assert_eq!(load_state(&path, f).unwrap().sequence, 3);
        assert!(deliver(&path, f, 2, Operation::Telemetry).is_err());
        assert_eq!(
            Appliance::load(&path).unwrap().system.hostname,
            "fleet-applied"
        );
        let mut provisional = next.clone();
        provisional.system.hostname = "fleet-explicit-revert".into();
        deliver(
            &path,
            f,
            4,
            Operation::Apply {
                expected_revision: crate::ha::revision(&next).unwrap(),
                toml: provisional.to_toml().unwrap(),
            },
        )
        .unwrap();
        let id = safe_apply::status(&path).unwrap()["pending"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        deliver(&path, f, 5, Operation::Revert { id }).unwrap();
        assert_eq!(
            Appliance::load(&path).unwrap().system.hostname,
            "fleet-applied"
        );
        assert_eq!(
            safe_apply::status(&path).unwrap()["last_result"]["outcome"],
            "reverted"
        );
        assert_eq!(load_state(&path, f).unwrap().sequence, 5);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    #[test]
    fn refused_or_expired_revisions_never_change_trust_or_restore_an_old_sequence() {
        let (path, a) = fixture();
        let f = a.fleet.as_ref().unwrap();
        let mut next = a.clone();
        next.fleet = None;
        assert!(
            deliver(
                &path,
                f,
                1,
                Operation::Apply {
                    expected_revision: crate::ha::revision(&a).unwrap(),
                    toml: next.to_toml().unwrap()
                }
            )
            .is_err()
        );
        next = a.clone();
        next.system.hostname = "must-revert".into();
        assert!(
            deliver(
                &path,
                f,
                2,
                Operation::Apply {
                    expected_revision: "stale".into(),
                    toml: next.to_toml().unwrap()
                }
            )
            .is_err()
        );
        deliver(
            &path,
            f,
            3,
            Operation::Apply {
                expected_revision: crate::ha::revision(&a).unwrap(),
                toml: next.to_toml().unwrap(),
            },
        )
        .unwrap();
        let id = safe_apply::status(&path).unwrap()["pending"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        safe_apply::recover(&path, &Apply::off(), true, false).unwrap();
        assert!(
            deliver(
                &path,
                f,
                4,
                Operation::Confirm {
                    id,
                    revision: crate::ha::revision(&next).unwrap()
                }
            )
            .is_err()
        );
        assert_eq!(Appliance::load(&path).unwrap().system.hostname, "working");
        assert_eq!(load_state(&path, f).unwrap().sequence, 4);
        std::fs::write(state_path(&path), "broken").unwrap();
        assert!(load_state(&path, f).is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    /// Every class of local trust anchor is refused on the fleet road, by name,
    /// and the refusal leaves the saved configuration and pending state alone;
    /// the same delivery path still accepts an ordinary policy change.
    #[test]
    fn fleet_apply_refuses_every_local_only_trust_section() {
        let (path, a) = fixture();
        let f = a.fleet.as_ref().unwrap();
        let base = a.to_toml().unwrap();
        let cases = [
            (
                "system.login",
                "[[system.login]]\nusername = \"mallory\"\n\
                 ssh-key = [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc mallory@controller\"]\n",
            ),
            (
                "system.group",
                "[[system.group]]\nname = \"ops\"\npermission = \"read-write\"\n",
            ),
            (
                "system.aaa",
                "[[system.aaa.radius]]\nserver = \"192.0.2.9\"\nsecret = \"controller-chosen\"\n",
            ),
            (
                "update",
                "[update]\nurl = \"https://updates.attacker.example/sentinel\"\n\
                 public-key = \"file:/var/lib/sentinel/attacker.pem\"\n",
            ),
            ("system.ha", "[system.ha]\nwitness = \"192.0.2.10:5400\"\n"),
            (
                "system.ha-witness",
                "[system.ha-witness]\nlisten = \"0.0.0.0:5400\"\nsecret = \"controller-chosen-witness-secret-0123456789\"\n",
            ),
            (
                "system.config-sync",
                "[system.config-sync]\npeer = [\"192.0.2.11\"]\nsecret = \"controller-chosen-sync\"\n",
            ),
            (
                "system.conntrack-sync",
                "[system.conntrack-sync]\npeer = [\"192.0.2.12\"]\n",
            ),
            (
                "services.ssh",
                "[services.ssh]\npassword-authentication = true\n",
            ),
            (
                "services.web",
                "[services.web]\nenable = true\nlisten-address = \"0.0.0.0\"\n",
            ),
            (
                "system.console",
                "[system.console]\ndevice = \"ttyS0\"\nspeed = 9600\n",
            ),
        ];
        for (sequence, (section, fragment)) in (1..).zip(cases) {
            let toml = format!("{base}\n{fragment}");
            Appliance::from_toml(&toml)
                .unwrap_or_else(|e| panic!("{section} fixture must be schema-valid: {e:#}"));
            let error = deliver(
                &path,
                f,
                sequence,
                Operation::Apply {
                    expected_revision: crate::ha::revision(&a).unwrap(),
                    toml,
                },
            )
            .expect_err(section);
            assert!(
                error.to_string().contains(section) && error.to_string().contains("local-only"),
                "{section}: {error:#}"
            );
            assert!(safe_apply::status(&path).unwrap()["pending"].is_null());
        }
        let mut rotated = a.clone();
        rotated.fleet.as_mut().unwrap().poll_interval = Some(30);
        let error = deliver(
            &path,
            f,
            100,
            Operation::Apply {
                expected_revision: crate::ha::revision(&a).unwrap(),
                toml: rotated.to_toml().unwrap(),
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("(fleet)"), "{error:#}");
        assert_eq!(Appliance::load(&path).unwrap().system.hostname, "working");

        let mut policy = a.clone();
        policy.system.hostname = "edge-policy".into();
        policy.system.timezone = Some("Europe/Berlin".into());
        deliver(
            &path,
            f,
            101,
            Operation::Apply {
                expected_revision: crate::ha::revision(&a).unwrap(),
                toml: policy.to_toml().unwrap(),
            },
        )
        .unwrap();
        assert!(
            safe_apply::status(&path).unwrap()["pending"]["ready"]
                .as_bool()
                .unwrap()
        );
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    /// The check-in curl starts from an empty environment with `--disable`
    /// first; the only variable it is handed is PATH, which curl never reads.
    #[test]
    fn the_check_in_request_ignores_curlrc_and_the_ambient_environment() {
        let command = check_in_command(&identity());
        let args: Vec<_> = command.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(args.first(), Some(&"--disable"), "{args:?}");
        assert_eq!(
            args.last(),
            Some(&"https://fleet.example/api/v1/sentinel/check-in")
        );
        assert!(
            !args
                .iter()
                .any(|a| a.contains("test-enrollment-credential"))
        );
        let envs: Vec<_> = command
            .get_envs()
            .map(|(k, _)| k.to_str().unwrap())
            .collect();
        assert!(envs.iter().all(|k| *k == "PATH"), "{envs:?}");
    }
    /// A `file:` token can only name a file directly in the fleet credential
    /// directory, and is read without following a link at the directory or at
    /// the file — so it cannot be aimed at another root-owned 0600 file.
    #[test]
    fn an_enrollment_token_file_is_confined_to_the_credential_directory() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        for good in [
            "file:/var/lib/sentinel/fleet/token",
            "inline-token-value-xyz",
        ] {
            let mut f = identity();
            f.enrollment_token = good.into();
            validate(&f).unwrap_or_else(|e| panic!("{good}: {e:#}"));
        }
        for bad in [
            "file:/etc/ssh/ssh_host_ed25519_key",
            "file:/var/lib/sentinel/fleet/../.appliance.toml.fleet.json",
            "file:/var/lib/sentinel/fleet/sub/token",
            "file:/var/lib/sentinel/fleet/",
            "file:/var/lib/sentinel/fleetx/token",
            "file:relative/token-file-name",
        ] {
            let mut f = identity();
            f.enrollment_token = bad.into();
            assert!(validate(&f).is_err(), "{bad}");
        }

        let (path, _) = fixture();
        let root = path.parent().unwrap();
        let dir = root.join("fleet");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let write_private = |p: &Path, text: &str| {
            std::fs::write(p, text).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        write_private(&dir.join("token"), "fleet-enrollment-credential\n");
        assert_eq!(
            private_credential_in(&dir, "token").unwrap(),
            "fleet-enrollment-credential"
        );
        // A link planted as the token, pointing at a private file elsewhere.
        let outside = root.join("outside-secret");
        write_private(&outside, "some-other-private-secret");
        symlink(&outside, dir.join("link")).unwrap();
        assert!(private_credential_in(&dir, "link").is_err());
        // The directory itself replaced by a link.
        symlink(root, root.join("fleet-link")).unwrap();
        assert!(private_credential_in(&root.join("fleet-link"), "outside-secret").is_err());
        // A directory others may write to cannot vouch for its entries.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(private_credential_in(&dir, "token").is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(dir.join("token"), std::fs::Permissions::from_mode(0o640))
            .unwrap();
        assert!(private_credential_in(&dir, "token").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn a_local_identity_rotation_invalidates_an_in_flight_controller_command() {
        let (path, mut a) = fixture();
        let old = a.fleet.clone().unwrap();
        a.fleet.as_mut().unwrap().node_id = "re-enrolled".into();
        crate::session::persist_appliance(&a, &path, false).unwrap();
        assert!(deliver(&path, &old, 1, Operation::Telemetry).is_err());
        assert!(!state_path(&path).exists());
        let current = a.fleet.as_ref().unwrap();
        deliver(&path, current, 9, Operation::Telemetry).unwrap();
        assert!(acknowledge_telemetry(&path, &old, 9, &Apply::off()).is_err());
        let state = load_state(&path, current).unwrap();
        assert_eq!(state.sequence, 9);
        assert!(state.telemetry_requested);
        acknowledge_telemetry(&path, current, 8, &Apply::off()).unwrap();
        assert!(load_state(&path, current).unwrap().telemetry_requested);
        acknowledge_telemetry(&path, current, 9, &Apply::off()).unwrap();
        assert!(!load_state(&path, current).unwrap().telemetry_requested);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    #[test]
    fn cli_document_roundtrip_keeps_all_fields_and_masks_only_the_reading_copy() {
        let (path, a) = fixture();
        let commands = crate::session::flatten_config(&crate::session::render_appliance(&a));
        let mut session = crate::session::Session::load(&path).unwrap();
        for command in commands {
            let words = crate::repl::split_line(&command);
            let refs: Vec<_> = words.iter().skip(1).map(String::as_str).collect();
            session.set(&refs).unwrap();
        }
        assert_eq!(session.commit().unwrap().fleet, a.fleet);
        assert!(
            !crate::session::render_appliance_for_reading(&a)
                .contains("test-enrollment-credential")
        );
        assert!(
            session
                .set(&["fleet", "enrollment-token", crate::session::KEY_NOT_SHOWN])
                .is_err()
        );
        session.delete(&["fleet"]).unwrap();
        assert!(session.commit().unwrap().fleet.is_none());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
