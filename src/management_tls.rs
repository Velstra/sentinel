//! Durable creation of the management identity before HTTPS can publish it.
use anyhow::{Context, Result, bail, ensure};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn artifact(path: &Path, private: bool) -> Result<Option<File>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("opening management TLS artifact {}", path.display()));
        }
    };
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no memory-safety preconditions.
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.len() > 0
            && metadata.len() <= 65_536,
        "management TLS artifact must be a nonempty regular file owned by this service: {}",
        path.display()
    );
    if private {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .context("securing the management private key")?;
    } else {
        ensure!(
            metadata.mode() & 0o022 == 0,
            "management certificate is writable by another account"
        );
    }
    Ok(Some(file))
}

fn directory(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening TLS directory {}", path.display()))
}

fn public_key(openssl: &Path, path: &Path, certificate: bool) -> Result<Vec<u8>> {
    let mut command = Command::new(openssl);
    if certificate {
        command.args(["x509", "-pubkey", "-noout", "-in"]);
    } else {
        command.args(["pkey", "-pubout", "-in"]);
    }
    let output = command
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .context("validating the management TLS identity")?;
    ensure!(
        output.status.success(),
        "management TLS artifact is invalid: {}",
        path.display()
    );
    Ok(output.stdout)
}

fn validate_pair(openssl: &Path, cert: &Path, key: &Path) -> Result<()> {
    ensure!(
        public_key(openssl, cert, true)? == public_key(openssl, key, false)?,
        "management certificate and private key do not match"
    );
    Ok(())
}

fn publish(staged: &Path, destination: &Path, parent: &File) -> Result<()> {
    // An atomic no-replace publication. Both names are on the same filesystem;
    // the private staging directory keeps the second link inaccessible.
    fs::hard_link(staged, destination).with_context(|| {
        format!(
            "publishing management TLS artifact {}",
            destination.display()
        )
    })?;
    parent
        .sync_all()
        .context("syncing management TLS publication")
}

/// A private key is the identity anchor: publish and sync it before its public
/// certificate. A crash between the two leaves a recoverable key-only state.
/// Never replace an existing identity or mistake permission errors for absence.
pub fn ensure_pair(cert: &Path, key: &Path, cn: &str, san: &str, openssl: &Path) -> Result<()> {
    let parent = cert
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let key_parent = key
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure!(
        parent == key_parent && cert != key,
        "management TLS files must have distinct names in one directory"
    );
    // Remember every new directory entry: syncing a file or the new directory
    // alone does not make its entry in its own parent survive a power loss.
    let mut created = Vec::new();
    let mut cursor = parent;
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                created.push(cursor.to_path_buf());
                cursor = cursor
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
            }
            Err(error) => return Err(error).context("inspecting management TLS directory"),
        }
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(parent)?;
    let parent_fd = directory(parent)?;
    let metadata = parent_fd.metadata()?;
    // SAFETY: geteuid has no memory-safety preconditions.
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0,
        "management TLS directory must be owned by this service and not writable by other accounts"
    );
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(parent.join(".generation.lock"))?;
    let metadata = lock.metadata()?;
    // SAFETY: geteuid has no memory-safety preconditions.
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.nlink() == 1
            && metadata.mode() & 0o777 == 0o600,
        "unsafe management TLS generation lock"
    );
    loop {
        // SAFETY: this descriptor stays open through validation and publication.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("locking management TLS generation");
        }
    }
    let existing_key = artifact(key, true)?;
    let existing_cert = artifact(cert, false)?;
    if existing_cert.is_some() && existing_key.is_none() {
        bail!("management private key is missing; refusing to replace the published identity");
    }
    if existing_cert.is_none() {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|e| anyhow::anyhow!("TLS staging entropy: {e}"))?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let stage = Staging(parent.join(format!(".generation-{suffix}")));
        fs::DirBuilder::new().mode(0o700).create(&stage.0)?;
        let staged_cert = stage.0.join("cert.pem");
        let staged_key = stage.0.join("key.pem");
        let mut command = Command::new(openssl);
        command.args(["req", "-x509", "-sha256", "-days", "3650", "-nodes"]);
        if existing_key.is_some() {
            command.arg("-key").arg(key);
        } else {
            command
                .args(["-newkey", "rsa:2048", "-keyout"])
                .arg(&staged_key);
        }
        let output = command
            .arg("-out")
            .arg(&staged_cert)
            .arg("-subj")
            .arg(format!("/CN={cn}"))
            .arg("-addext")
            .arg(san)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .context("minting the management TLS certificate")?;
        ensure!(
            output.status.success(),
            "openssl could not mint the management TLS certificate: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&staged_cert)?
            .set_permissions(fs::Permissions::from_mode(0o644))?;
        let selected_key = if existing_key.is_some() {
            key
        } else {
            &staged_key
        };
        let key_fd = artifact(selected_key, true)?.context("generated management key missing")?;
        let cert_fd =
            artifact(&staged_cert, false)?.context("generated management certificate missing")?;
        validate_pair(openssl, &staged_cert, selected_key)?;
        key_fd
            .sync_all()
            .context("syncing the management private key")?;
        cert_fd
            .sync_all()
            .context("syncing the management certificate")?;
        if existing_key.is_none() {
            publish(&staged_key, key, &parent_fd)?;
        }
        publish(&staged_cert, cert, &parent_fd)?;
    } else {
        validate_pair(openssl, cert, key)?;
        existing_key
            .as_ref()
            .context("management private key missing")?
            .sync_all()?;
        existing_cert
            .as_ref()
            .context("management certificate missing")?
            .sync_all()?;
    }
    parent_fd
        .sync_all()
        .context("syncing the management TLS directory")?;
    for path in created {
        directory(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()
        .context("syncing the management TLS directory ancestry")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let mut nonce = [0u8; 16];
            getrandom::getrandom(&mut nonce).unwrap();
            let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let path = std::env::temp_dir().join(format!("sentinel-management-tls-{suffix}"));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn ensure(&self) -> Result<()> {
            crate::system::ensure_self_signed_cert(
                &self.0.join("cert.pem"),
                &self.0.join("key.pem"),
                "fw",
                &["127.0.0.1".into()],
            )
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn concurrent_generation_publishes_one_matching_private_identity() {
        let dir = Arc::new(TestDirectory::new());
        let barrier = Arc::new(Barrier::new(6));
        let workers: Vec<_> = (0..6)
            .map(|_| {
                let dir = dir.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    dir.ensure().unwrap();
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        let key = fs::read(dir.0.join("key.pem")).unwrap();
        let cert = fs::read(dir.0.join("cert.pem")).unwrap();
        dir.ensure().unwrap();
        assert_eq!(fs::read(dir.0.join("key.pem")).unwrap(), key);
        assert_eq!(fs::read(dir.0.join("cert.pem")).unwrap(), cert);
        assert_eq!(
            fs::metadata(dir.0.join("key.pem")).unwrap().mode() & 0o777,
            0o600
        );
        assert!(fs::read_dir(&dir.0).unwrap().all(|item| {
            !item
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".generation-")
        }));
    }

    #[test]
    fn interrupted_key_only_publication_recovers_without_rotating_the_key() {
        let dir = TestDirectory::new();
        dir.ensure().unwrap();
        let key = fs::read(dir.0.join("key.pem")).unwrap();
        let pin = crate::system::cert_pubkey_pin(&dir.0.join("cert.pem")).unwrap();
        fs::remove_file(dir.0.join("cert.pem")).unwrap();
        dir.ensure().unwrap();
        assert_eq!(fs::read(dir.0.join("key.pem")).unwrap(), key);
        assert_eq!(
            crate::system::cert_pubkey_pin(&dir.0.join("cert.pem")).unwrap(),
            pin
        );
    }

    #[test]
    fn a_missing_private_key_cannot_silently_replace_a_published_identity() {
        let dir = TestDirectory::new();
        dir.ensure().unwrap();
        let cert = fs::read(dir.0.join("cert.pem")).unwrap();
        fs::remove_file(dir.0.join("key.pem")).unwrap();
        assert!(
            dir.ensure()
                .unwrap_err()
                .to_string()
                .contains("refusing to replace")
        );
        assert_eq!(fs::read(dir.0.join("cert.pem")).unwrap(), cert);
        assert!(!dir.0.join("key.pem").exists());
    }

    #[test]
    fn symlink_artifacts_and_generation_locks_are_rejected() {
        use std::os::unix::fs::symlink;
        let dir = TestDirectory::new();
        let victim = dir.0.join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        symlink(&victim, dir.0.join(".generation.lock")).unwrap();
        assert!(dir.ensure().is_err());
        fs::remove_file(dir.0.join(".generation.lock")).unwrap();
        symlink(&victim, dir.0.join("key.pem")).unwrap();
        assert!(dir.ensure().is_err());
        assert_eq!(fs::read(victim).unwrap(), b"unchanged");
    }

    #[test]
    fn mismatched_existing_pair_is_an_error_and_is_never_replaced() {
        let first = TestDirectory::new();
        let second = TestDirectory::new();
        first.ensure().unwrap();
        second.ensure().unwrap();
        let unrelated = fs::read(second.0.join("cert.pem")).unwrap();
        fs::write(first.0.join("cert.pem"), &unrelated).unwrap();
        let original_key = fs::read(first.0.join("key.pem")).unwrap();
        assert!(
            first
                .ensure()
                .unwrap_err()
                .to_string()
                .contains("do not match")
        );
        assert_eq!(fs::read(first.0.join("key.pem")).unwrap(), original_key);
        assert_eq!(fs::read(first.0.join("cert.pem")).unwrap(), unrelated);
    }
}
