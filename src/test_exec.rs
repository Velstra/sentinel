//! Stub executables for tests that run one.
//!
//! The test binary runs its tests on parallel threads, and many of them fork.
//! A stub this process writes itself is open for writing until the write
//! ends. A thread that forks in that window hands its child a copy of the
//! write descriptor, which `O_CLOEXEC` closes only at that child's own exec.
//! Running the stub while such a child sits between fork and exec fails with
//! ETXTBSY ("Text file busy"). So a child shell writes the stub: this process
//! never opens it for writing, and once that shell has exited no process
//! holds it open.

use std::path::Path;
use std::process::Command;

/// Create the executable `path` with `contents` and permission bits `mode`.
pub(crate) fn write_executable(path: &Path, contents: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    // `printf` and the redirection are shell built-ins, so the shell is the
    // only process that ever opens the stub for writing.
    let status = Command::new("/bin/sh")
        .args(["-c", "umask 077 && printf '%s' \"$2\" > \"$1\"", "sh"])
        .arg(path)
        .arg(contents)
        .status()
        .unwrap();
    assert!(status.success(), "writing {}: {status}", path.display());
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(test)]
mod tests {
    use super::write_executable;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const WRITERS: usize = 8;
    const FORKERS: usize = 8;
    const ROUNDS: usize = 200;

    /// Writers create and run fresh stubs while other threads fork and exec
    /// without pause, as the rest of the test binary does. Not one exec may fail
    /// with ETXTBSY. Run it with
    /// `cargo test -- --ignored stubs_run_while_other_threads_fork`.
    #[test]
    #[ignore = "stress harness: seconds of fork load"]
    fn stubs_run_while_other_threads_fork() {
        let dir = std::env::temp_dir().join(format!("sentinel-test-exec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let forkers: Vec<_> = (0..FORKERS)
            .map(|_| {
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let _ = Command::new("/bin/sh").args(["-c", ":"]).status();
                    }
                })
            })
            .collect();
        let busy = Arc::new(AtomicUsize::new(0));
        let writers: Vec<_> = (0..WRITERS)
            .map(|writer| {
                let (dir, busy) = (dir.clone(), Arc::clone(&busy));
                std::thread::spawn(move || {
                    for round in 0..ROUNDS {
                        let stub = dir.join(format!("stub-{writer}-{round}"));
                        write_executable(&stub, "#!/bin/sh\nexit 0\n", 0o700);
                        match Command::new(&stub).status() {
                            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                                busy.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => panic!("running {}: {e}", stub.display()),
                            Ok(status) => assert!(status.success(), "{status}"),
                        }
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        for forker in forkers {
            forker.join().unwrap();
        }
        std::fs::remove_dir_all(&dir).unwrap();
        let busy = busy.load(Ordering::Relaxed);
        assert_eq!(
            busy,
            0,
            "{busy} of {} stub execs failed with ETXTBSY",
            WRITERS * ROUNDS
        );
    }
}
