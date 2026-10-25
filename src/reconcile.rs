//! Retryable service configuration updates. A file on disk is desired state,
//! not proof that the process has loaded it. Keep a non-secret pending marker
//! until activation succeeds, including when removing a configuration.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::{net::ApplyMode, system};

pub(crate) fn pending_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".sentinel-pending");
    PathBuf::from(name)
}

pub(crate) fn service_file(
    path: &Path,
    body: Option<&str>,
    mode: ApplyMode,
    install: impl FnOnce(&Path, &str) -> Result<()>,
    activate: impl FnOnce(bool) -> Result<()>,
) -> Result<()> {
    let pending = pending_path(path);
    let changed = match body {
        Some(body) => system::read_owned_file(path)?.as_deref() != Some(body),
        None => system::owned_file_exists(path)?,
    };
    let retry = system::owned_file_exists(&pending)?;
    if mode == ApplyMode::Live && (changed || retry) {
        // Written before touching the config: a crash between installation and
        // activation must be retried, too. No credentials in this marker.
        system::install_file(&pending, "pending\n")?;
    }
    match body {
        Some(body) => install(path, body)?,
        None if changed => system::remove_file(path)?,
        None => {}
    }
    if mode == ApplyMode::Live {
        activate(changed || retry).with_context(|| format!("activating {}", path.display()))?;
    }
    // Boot only renders: the ordered service start will read the new config.
    // Live reaches here only after successful activation (or a genuine no-op).
    if system::owned_file_exists(&pending)? {
        system::remove_file(&pending)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "sentinel-reconcile-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn failed_activation_retries_unchanged_config_and_then_settles() {
        let dir = dir();
        let path = dir.join("dns.conf");
        let calls = AtomicUsize::new(0);
        let apply = |fail: bool| {
            service_file(
                &path,
                Some("server=192.0.2.1\n"),
                ApplyMode::Live,
                system::install_file,
                |changed| {
                    if changed {
                        calls.fetch_add(1, Ordering::Relaxed);
                    }
                    anyhow::ensure!(!fail, "service failed");
                    Ok(())
                },
            )
        };
        assert!(apply(true).is_err());
        assert!(pending_path(&path).exists());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "server=192.0.2.1\n"
        );
        apply(false).unwrap();
        assert!(!pending_path(&path).exists());
        apply(false).unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_stop_is_retried_even_after_config_has_been_removed() {
        let dir = dir();
        let path = dir.join("dhcp6.conf");
        std::fs::write(&path, "interface=lan\n").unwrap();
        assert!(
            service_file(
                &path,
                None,
                ApplyMode::Live,
                system::install_file,
                |_| anyhow::bail!("stop failed")
            )
            .is_err()
        );
        assert!(!path.exists());
        assert!(pending_path(&path).exists());
        let calls = AtomicUsize::new(0);
        for _ in 0..2 {
            service_file(
                &path,
                None,
                ApplyMode::Live,
                system::install_file,
                |changed| {
                    if changed {
                        calls.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(())
                },
            )
            .unwrap();
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn boot_renders_without_activating_later_ordered_services() {
        let dir = dir();
        let path = dir.join("resolver.conf");
        service_file(
            &path,
            Some("DNS=192.0.2.53\n"),
            ApplyMode::Boot,
            system::install_file,
            |_| panic!("boot must not activate a service"),
        )
        .unwrap();
        assert!(path.exists());
        assert!(!pending_path(&path).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
