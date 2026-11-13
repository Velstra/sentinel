use super::*;
use crate::config::UpdateChannel;
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

fn offer() -> update::VerifiedOffer {
    update::VerifiedOffer {
        manifest: update::Manifest {
            version: "v1.2.0-lts".into(),
            image: "sentinel.raw".into(),
            sha256: "a".repeat(64),
            product: Some(update::PRODUCT.into()),
        },
        manifest_sha256: "b".repeat(64),
        public_key_sha256: "c".repeat(64),
    }
}
fn channel() -> UpdateChannel {
    UpdateChannel {
        name: Some("enterprise".into()),
        url: "https://updates.invalid/current".into(),
        public_key: "fixture-public-key".into(),
        subscription_key: Some("fixture-secret-not-for-argv-or-env".into()),
    }
}
fn staged() -> install::StagedImage {
    install::StagedImage {
        active_slot: "sentinel-a".into(),
        staged_slot: "sentinel-b".into(),
        verity_guid: "11111111-1111-1111-1111-111111111111".into(),
        store_guid: "22222222-2222-2222-2222-222222222222".into(),
        boot_entry: "sentinel_v1.2.0-lts+3-0.efi".into(),
        uki_sha256: "d".repeat(64),
    }
}

fn helper(scratch: &update::Scratch, before: &str, prepared: &str, after: &str) -> Command {
    let staged = serde_json::to_string(&staged()).unwrap();
    let body = format!(
        r#"
import json, os, sys, time
from pathlib import Path
root = Path(sys.argv[1])
(root / 'pid').write_text(str(os.getpid()))
assert not os.getenv('SENTINEL_NATIVE_TEST_SECRET')
assert all('fixture-secret' not in arg for arg in sys.argv)
request = json.loads(sys.stdin.readline())
assert set(request) == {{'schema', 'channel', 'expected'}}
assert request['schema'] == 1
assert request['channel']['subscription-key'] == 'fixture-secret-not-for-argv-or-env'
def send(event, **fields):
    print(json.dumps({{'schema':1, 'event':event, **fields}}), flush=True)
{before}
for phase in ['metadata', 'downloading', 'verifying', 'preflight']:
    send('phase', phase=phase)
token = 'e' * 64
prepared = {{'schema':1, 'event':'prepared', 'token':token, 'offer':request['expected']}}
{prepared}
print(json.dumps(prepared), flush=True)
permission = sys.stdin.readline()
assert permission and json.loads(permission) == {{'schema':1, 'event':'go', 'token':token}}
assert (root / 'journal').read_bytes() == b'durable-writing'
(root / 'go').write_text('received')
send('phase', phase='writing')
{after}
send('phase', phase='publishing')
send('complete', staged=json.loads({staged:?}))
"#
    );
    std::fs::write(scratch.join("provider.py"), body).unwrap();
    let mut command =
        Command::new(option_env!("SENTINEL_TEST_PYTHON_BIN").unwrap_or("/usr/bin/python3"));
    command.args([
        "-I",
        scratch.join("provider.py").to_str().unwrap(),
        scratch.join(".").to_str().unwrap(),
    ]);
    command.env("SENTINEL_NATIVE_TEST_SECRET", "must-be-cleared");
    command
}

fn invoke(
    command: Command,
    scratch: &update::Scratch,
    total: Duration,
    ipc: Duration,
    refuse: Option<install::UpdatePhase>,
    before: &mut dyn FnMut() -> Result<()>,
) -> (Result<install::StagedImage>, Vec<install::UpdatePhase>) {
    let phases = RefCell::new(Vec::new());
    let mut phase = |next| {
        phases.borrow_mut().push(next);
        ensure!(refuse != Some(next), "journal refused");
        if next == install::UpdatePhase::Writing {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(scratch.join("journal"))?;
            file.write_all(b"durable-writing")?;
            file.sync_all()?;
        }
        Ok(())
    };
    let result = run_with_deadlines(
        command,
        &channel(),
        &offer(),
        install::UpdateHooks {
            phase: &mut phase,
            before_write: before,
        },
        total,
        ipc,
    );
    (result, phases.into_inner())
}

#[test]
fn native_protocol_actual_pipes_require_durable_writing_before_go_and_owned_success_exit() {
    let scratch = update::Scratch::new().unwrap();
    let command = helper(&scratch, "sys.stderr.write('x' * 1048576)", "", "");
    let (result, phases) = invoke(
        command,
        &scratch,
        Duration::from_secs(3),
        Duration::from_secs(1),
        None,
        &mut || Ok(()),
    );
    assert_eq!(result.unwrap(), staged());
    assert_eq!(
        phases,
        [
            install::UpdatePhase::Metadata,
            install::UpdatePhase::Downloading,
            install::UpdatePhase::Verifying,
            install::UpdatePhase::Preflight,
            install::UpdatePhase::Writing,
            install::UpdatePhase::Publishing
        ]
    );
    assert!(scratch.join("go").exists());
    let pid: i32 = std::fs::read_to_string(scratch.join("pid"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "owned child was not reaped"
    );
}

#[test]
fn native_protocol_rejects_offer_token_and_nested_wire_shape_before_go() {
    for change in [
        "prepared['offer']['manifest']['version'] = 'v1.3.0-lts'",
        "prepared['offer']['manifest']['image'] = 'different.raw'",
        "prepared['offer']['manifest']['sha256'] = '0' * 64",
        "prepared['offer']['manifest']['product'] = 'foreign'",
        "prepared['offer']['manifest_sha256'] = '0' * 64",
        "prepared['offer']['public_key_sha256'] = '0' * 64",
        "prepared['offer']['manifest']['extra'] = True",
        "prepared['token'] = 'invalid'",
        "prepared['schema'] = True",
        "prepared['schema'] = 2",
        "prepared['extra'] = 'fixture-secret-not-for-argv-or-env'",
    ] {
        let scratch = update::Scratch::new().unwrap();
        let command = helper(&scratch, "", change, "");
        let (result, phases) = invoke(
            command,
            &scratch,
            Duration::from_secs(2),
            Duration::from_secs(1),
            None,
            &mut || Ok(()),
        );
        assert!(result.is_err(), "{change}");
        assert!(!phases.contains(&install::UpdatePhase::Writing), "{change}");
        assert!(!scratch.join("go").exists(), "{change}");
    }
}

#[test]
fn native_protocol_cas_journal_and_expired_preparation_never_send_go() {
    for mode in 0..3 {
        let scratch = update::Scratch::new().unwrap();
        let command = helper(&scratch, "", "", "");
        let mut before = || {
            if mode == 0 {
                bail!(crate::update_jobs::Error(
                    crate::update_jobs::Code::Conflict
                ));
            }
            if mode == 2 {
                std::thread::sleep(Duration::from_millis(80));
            }
            Ok(())
        };
        let (result, _) = invoke(
            command,
            &scratch,
            Duration::from_secs(2),
            if mode == 2 {
                Duration::from_millis(40)
            } else {
                Duration::from_secs(1)
            },
            (mode == 1).then_some(install::UpdatePhase::Writing),
            &mut before,
        );
        assert!(result.is_err());
        if mode == 0 {
            assert_eq!(
                result
                    .unwrap_err()
                    .downcast_ref::<crate::update_jobs::Error>()
                    .unwrap()
                    .0,
                crate::update_jobs::Code::Conflict
            );
        }
        assert!(!scratch.join("go").exists());
    }
}

#[test]
fn native_protocol_post_go_error_waits_for_actual_writer_and_does_not_kill_it() {
    let scratch = update::Scratch::new().unwrap();
    let command = helper(
        &scratch,
        "",
        "",
        "print('not-json', flush=True)\ntime.sleep(0.15)\n(root / 'writer-finished').write_text('complete')\nsys.exit(1)",
    );
    let started = Instant::now();
    let (result, _) = invoke(
        command,
        &scratch,
        Duration::from_secs(2),
        Duration::from_secs(1),
        None,
        &mut || Ok(()),
    );
    assert!(result.is_err());
    assert!(started.elapsed() >= Duration::from_millis(140));
    assert!(scratch.join("writer-finished").exists());
}

#[test]
fn native_protocol_pre_go_refusal_allows_owned_provider_cleanup() {
    let scratch = update::Scratch::new().unwrap();
    let command = helper(
        &scratch,
        "import atexit\natexit.register(lambda: (root / 'pre-go-cleanup').write_text('removed-resource-cache'))",
        "",
        "",
    );
    let (result, _) = invoke(
        command,
        &scratch,
        Duration::from_secs(2),
        Duration::from_secs(1),
        None,
        &mut || {
            bail!(crate::update_jobs::Error(
                crate::update_jobs::Code::Conflict
            ));
        },
    );
    assert_eq!(
        result
            .unwrap_err()
            .downcast_ref::<crate::update_jobs::Error>()
            .unwrap()
            .0,
        crate::update_jobs::Code::Conflict
    );
    assert_eq!(
        std::fs::read_to_string(scratch.join("pre-go-cleanup")).unwrap(),
        "removed-resource-cache"
    );
    assert!(!scratch.join("go").exists());
}

#[test]
fn native_protocol_panicking_publication_hook_still_waits_for_the_writer_group() {
    let scratch = update::Scratch::new().unwrap();
    let command = helper(
        &scratch,
        "",
        "",
        "pid = os.fork()\nif pid == 0:\n    os.close(1)\n    time.sleep(0.15)\n    (root / 'panic-writer-finished').write_text('complete')\n    os._exit(0)",
    );
    let mut phase = |phase| {
        if phase == install::UpdatePhase::Writing {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(scratch.join("journal"))?;
            file.write_all(b"durable-writing")?;
            file.sync_all()?;
        }
        assert_ne!(
            phase,
            install::UpdatePhase::Publishing,
            "publication hook fixture"
        );
        Ok(())
    };
    let result = run_with_deadlines(
        command,
        &channel(),
        &offer(),
        install::UpdateHooks {
            phase: &mut phase,
            before_write: &mut || Ok(()),
        },
        Duration::from_secs(2),
        Duration::from_secs(1),
    );
    assert!(result.is_err());
    assert!(scratch.join("panic-writer-finished").exists());
}

#[test]
fn native_protocol_dead_helper_does_not_abandon_the_orphaned_group_writer() {
    let scratch = update::Scratch::new().unwrap();
    let command = helper(
        &scratch,
        "",
        "",
        "pid = os.fork()\nif pid == 0:\n    os.close(1)\n    time.sleep(0.15)\n    (root / 'orphan-finished').write_text('complete')\n    os._exit(0)\nos._exit(1)",
    );
    let (result, _) = invoke(
        command,
        &scratch,
        Duration::from_secs(2),
        Duration::from_secs(1),
        None,
        &mut || Ok(()),
    );
    assert!(result.is_err());
    assert!(scratch.join("orphan-finished").exists());
}

#[test]
fn native_protocol_nonzero_exit_extra_terminal_frames_and_invalid_order_never_stage() {
    for tail in [
        "send('phase', phase='preflight')",
        "send('complete', staged={})",
        "send('error', code='fixture-secret-not-for-argv-or-env')",
    ] {
        let scratch = update::Scratch::new().unwrap();
        let command = helper(&scratch, "", "", tail);
        let (result, _) = invoke(
            command,
            &scratch,
            Duration::from_secs(2),
            Duration::from_secs(1),
            None,
            &mut || Ok(()),
        );
        let error = result.unwrap_err();
        assert!(!format!("{error:#}").contains("fixture-secret"));
    }
    for suffix in ["\nsys.exit(7)\n", "\nsend('error', code='refused')\n"] {
        let scratch = update::Scratch::new().unwrap();
        let command = helper(&scratch, "", "", "");
        let path = scratch.join("provider.py");
        let mut stream = OpenOptions::new().append(true).open(path).unwrap();
        stream.write_all(suffix.as_bytes()).unwrap();
        assert!(
            invoke(
                command,
                &scratch,
                Duration::from_secs(2),
                Duration::from_secs(1),
                None,
                &mut || Ok(())
            )
            .0
            .is_err()
        );
    }
}

#[test]
fn native_protocol_prewrite_deadline_kills_and_reaps_without_authorizing() {
    let scratch = update::Scratch::new().unwrap();
    let command = helper(&scratch, "time.sleep(10)", "", "");
    let begin = Instant::now();
    assert!(
        invoke(
            command,
            &scratch,
            Duration::from_millis(150),
            Duration::from_millis(100),
            None,
            &mut || Ok(())
        )
        .0
        .is_err()
    );
    assert!(begin.elapsed() < Duration::from_secs(2));
    assert!(!scratch.join("go").exists());
}

#[test]
fn native_protocol_frame_parser_rejects_duplicates_noninteger_schema_and_oversize() {
    for line in [
        "{\"event\":\"phase\",\"event\":\"phase\",\"schema\":1,\"phase\":\"metadata\"}",
        "{\"event\":\"phase\",\"schema\":1,\"schema\":1,\"phase\":\"metadata\"}",
        "{\"event\":\"phase\",\"schema\":true,\"phase\":\"metadata\"}",
        "{\"event\":\"phase\",\"schema\":1.0,\"phase\":\"metadata\"}",
        "{\"event\":\"phase\",\"schema\":1,\"phase\":\"metadata\",\"extra\":0}",
    ] {
        assert!(serde_json::from_str::<Frame>(line).is_err(), "{line}");
    }
    let mut reader = std::io::Cursor::new(vec![b'x'; MAX_RESPONSE + 1]);
    assert!(
        receive(
            &mut reader,
            &mut Vec::new(),
            Instant::now() + Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(!live_group_member(
        b"1 (name with ) parentheses) Z 0 123 0",
        123
    ));
    assert!(live_group_member(
        b"1 (name with ) parentheses) S 0 123 0",
        123
    ));
    assert!(!live_group_member(b"1 (name) S 0 999 0", 123));
    assert!(live_group_member(b"1 (non-UTF8-\xff) S 0 123 0", 123));
}
