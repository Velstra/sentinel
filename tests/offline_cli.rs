//! Real process/exit-status regressions; no daemon or privilege helper is used.
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "sentinel-offline-cli-{}-{:032x}",
            std::process::id(),
            u128::from_ne_bytes(nonce)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            path.join("config.toml"),
            "[system]\nhostname = \"edge-a\"\n",
        )
        .unwrap();
        Self(path)
    }
    fn configure(&self, script: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .args(["configure", "--no-apply", "--config"])
            .arg(self.0.join("config.toml"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn invalid_show_and_failed_operational_commands_stop_before_save() {
    let fixture = Fixture::new();
    let path = fixture.0.join("config.toml");
    let before = fs::read(&path).unwrap();
    for command in [
        "show configuration",
        "show nonexistent",
        "run show nonexistent",
    ] {
        let result = fixture.configure(&format!("set system hostname changed\n{command}\nsave\n"));
        assert!(!result.status.success(), "{command}: {result:?}");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(String::from_utf8_lossy(&result.stderr).contains("batch stopped"));
    }
    let result =
        fixture.configure("show system\nrun --version\nset system hostname edge-b\ncommit\nsave\n");
    assert!(result.status.success(), "{result:?}");
    assert!(fs::read_to_string(path).unwrap().contains("edge-b"));
}

#[test]
fn offline_export_in_root_owned_tmp_needs_no_runtime_directory() {
    let fixture = Fixture::new();
    let basename = fixture.0.file_name().unwrap();
    let target = Path::new("/tmp").join(basename).with_extension("toml");
    // create_new means the fixture never overwrites somebody else's pathname.
    let mut reserved = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .unwrap();
    reserved
        .write_all(b"[system]\nhostname = \"previous\"\n")
        .unwrap();
    drop(reserved);
    let result = fixture.configure(&format!(
        "set system hostname exported\ncommit\nsave {}\n",
        target.display()
    ));
    let contents = fs::read_to_string(&target).unwrap();
    let metadata = fs::metadata(&target).unwrap();
    fs::remove_file(&target).unwrap();
    let lock = target.with_extension("transaction.lock");
    if lock.exists() {
        fs::remove_file(lock).unwrap();
    }
    assert!(result.status.success(), "{result:?}");
    assert!(contents.contains("exported"));
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert!(
        fs::read_to_string(fixture.0.join("config.toml"))
            .unwrap()
            .contains("edge-a")
    );
}

#[test]
fn offline_export_refuses_a_destination_symlink_without_touching_its_target() {
    let fixture = Fixture::new();
    let victim = fixture.0.join("victim.toml");
    let link = fixture.0.join("linked.toml");
    let original = "[system]\nhostname = \"preserved\"\n";
    fs::write(&victim, original).unwrap();
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let result = fixture.configure(&format!("save {}\n", link.display()));
    assert!(!result.status.success());
    // Admission rejects the link before the writer is reached. Both layers
    // must preserve the target; the writer's own diagnostic is unit-tested.
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("reading admission saved intent"),
        "{result:?}"
    );
    assert_eq!(fs::read_to_string(victim).unwrap(), original);
    assert!(link.is_symlink());
}
