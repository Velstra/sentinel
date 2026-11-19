//! Keep an interactive commit running to its end — applied or rolled back —
//! when the terminal that started it goes away (CTRL-15).
//!
//! A plain `commit` reloads the data plane, then routing, then reconciles
//! networkd and the co-services, and records RUNNING last. Commit-confirm and
//! the API run that inside a journalled transaction a separate unit recovers;
//! the CLI commit ran it in the operator's process, and that process was easy
//! to kill halfway: Ctrl-C, the SIGHUP of an SSH session the commit itself
//! cut, or the first `eprintln!` after the hang-up, which fails with EIO and
//! panics. What was left was a half-applied box with a stale RUNNING that
//! every later refresh compiled over.
//!
//! While a [`Guard`] lives, the signals that end an interactive process are
//! caught (and reported afterwards) rather than acted on, and standard output
//! and error are relayed through pipes this process owns, so a write after the
//! terminal has gone cannot fail. Handlers, unlike an ignored disposition, are
//! reset by `exec`, so the commands a commit runs keep their normal signals.

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

/// The signals an operator, a terminal or a session teardown sends.
const DEFERRED: [libc::c_int; 6] = [
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGTERM,
    libc::SIGQUIT,
    libc::SIGTSTP,
    libc::SIGPIPE,
];

/// The last signal deferred while a guard was held (0: none).
static DEFERRED_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn defer(signal: libc::c_int) {
    // Async-signal-safe: a single atomic store.
    DEFERRED_SIGNAL.store(signal, Ordering::Relaxed);
}

/// Install the recording handler for `signals`, returning what it replaced.
fn defer_signals(signals: &[libc::c_int]) -> Vec<(libc::c_int, libc::sigaction)> {
    let mut previous = Vec::new();
    for &signal in signals {
        // SAFETY: a zeroed sigaction is a valid starting value; the handler
        // only performs an atomic store.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = defer as extern "C" fn(libc::c_int) as usize;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            let mut old: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(signal, &action, &mut old) == 0 {
                previous.push((signal, old));
            }
        }
    }
    previous
}

/// Holds the deferred signals and the output relays; dropping it restores both.
pub(crate) struct Guard {
    previous: Vec<(libc::c_int, libc::sigaction)>,
    relays: Vec<Relay>,
}

impl Guard {
    /// Defer interrupts and protect standard output and error. Best effort: a
    /// relay that cannot be set up leaves that stream as it was.
    pub(crate) fn enter() -> Self {
        DEFERRED_SIGNAL.store(0, Ordering::Relaxed);
        let previous = defer_signals(&DEFERRED);
        let relays = [libc::STDOUT_FILENO, libc::STDERR_FILENO]
            .into_iter()
            .filter_map(|fd| Relay::install(fd).ok())
            .collect();
        Self { previous, relays }
    }

    /// The signal that arrived while the guard was held, if any.
    pub(crate) fn deferred(&self) -> Option<libc::c_int> {
        match DEFERRED_SIGNAL.load(Ordering::Relaxed) {
            0 => None,
            signal => Some(signal),
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        use std::io::Write;
        let _ = std::io::stdout().flush();
        for relay in self.relays.drain(..) {
            relay.restore();
        }
        for (signal, old) in self.previous.drain(..) {
            // SAFETY: restoring the disposition sigaction returned earlier.
            unsafe {
                libc::sigaction(signal, &old, std::ptr::null_mut());
            }
        }
    }
}

/// One stream redirected into a pipe whose reader forwards to the original
/// destination and ignores its errors.
struct Relay {
    target: RawFd,
    original: RawFd,
    done: std::sync::mpsc::Receiver<()>,
}

impl Relay {
    fn install(target: RawFd) -> std::io::Result<Self> {
        let last = std::io::Error::last_os_error;
        // SAFETY: plain descriptor syscalls on descriptors this function owns;
        // every failure path closes what it opened.
        unsafe {
            let original = libc::fcntl(target, libc::F_DUPFD_CLOEXEC, 3);
            if original < 0 {
                return Err(last());
            }
            let mut fds = [0; 2];
            if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
                let error = last();
                libc::close(original);
                return Err(error);
            }
            let [read, write] = fds;
            let (sender, done) = std::sync::mpsc::channel();
            let forward = std::thread::Builder::new()
                .name("commit-output".into())
                .spawn(move || {
                    forward(read, original);
                    let _ = sender.send(());
                });
            if forward.is_err() {
                let error = last();
                libc::close(write);
                libc::close(read);
                libc::close(original);
                return Err(error);
            }
            if libc::dup2(write, target) < 0 {
                // The forwarder owns `read` and `original`; closing the only
                // write end lets it see end-of-file and close them itself.
                let error = last();
                libc::close(write);
                return Err(error);
            }
            libc::close(write);
            Ok(Self {
                target,
                original,
                done,
            })
        }
    }

    /// Point the stream back at its original destination. That closes the last
    /// write end this process holds, so the forwarder drains and exits. A child
    /// that kept the pipe open would keep it alive; it is not waited for long.
    fn restore(self) {
        // SAFETY: `original` stays open until the forwarder exits.
        unsafe {
            libc::dup2(self.original, self.target);
        }
        let _ = self.done.recv_timeout(Duration::from_millis(500));
    }
}

/// Copy everything from `read` to `write`, never failing on a vanished sink.
fn forward(read: RawFd, write: RawFd) {
    let mut buffer = [0u8; 8192];
    let mut sink_alive = true;
    loop {
        // SAFETY: reading into a local buffer from a pipe this thread owns.
        let n = unsafe { libc::read(read, buffer.as_mut_ptr().cast(), buffer.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        let mut offset = 0;
        while sink_alive && offset < n as usize {
            // SAFETY: writing bytes just read into the local buffer.
            let written = unsafe {
                libc::write(write, buffer[offset..].as_ptr().cast(), n as usize - offset)
            };
            if written < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                // EIO after a hang-up, EPIPE on a closed pipe: keep draining
                // so the writers never block or fail, but stop forwarding.
                sink_alive = false;
            } else {
                offset += written as usize;
            }
        }
    }
    // SAFETY: both descriptors belong to this thread now.
    unsafe {
        libc::close(read);
        libc::close(write);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relay_never_fails_a_write_when_its_destination_is_gone() {
        // Stand-in for a terminal that hung up: the protected descriptor points
        // at a pipe nobody reads any more.
        let mut sink = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(sink.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let [sink_read, sink_write] = sink;
        unsafe { libc::close(sink_read) };
        let protected = unsafe { libc::fcntl(sink_write, libc::F_DUPFD_CLOEXEC, 100) };
        assert!(protected >= 0);
        unsafe { libc::close(sink_write) };
        let previous = unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            let mut ignore: libc::sigaction = std::mem::zeroed();
            ignore.sa_sigaction = libc::SIG_IGN;
            libc::sigaction(libc::SIGPIPE, &ignore, &mut old);
            old
        };
        let unprotected = unsafe { libc::write(protected, b"x".as_ptr().cast(), 1) };
        assert_eq!(unprotected, -1, "the stand-in destination must be broken");
        let relay = Relay::install(protected).unwrap();
        for _ in 0..64 {
            let written = unsafe { libc::write(protected, [b'y'; 4096].as_ptr().cast(), 4096) };
            assert_eq!(written, 4096, "a write through the relay failed");
        }
        relay.restore();
        unsafe {
            libc::sigaction(libc::SIGPIPE, &previous, std::ptr::null_mut());
            libc::close(protected);
        }
    }

    #[test]
    fn a_hang_up_during_the_guard_is_deferred_and_reported() {
        let guard = Guard {
            previous: Vec::new(),
            relays: Vec::new(),
        };
        // Install only the handlers, without touching the test harness's output.
        let installed = defer_signals(&[libc::SIGHUP]);
        assert_eq!(installed.len(), 1);
        DEFERRED_SIGNAL.store(0, Ordering::Relaxed);
        assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
        assert_eq!(guard.deferred(), Some(libc::SIGHUP));
        drop(Guard {
            previous: installed,
            relays: Vec::new(),
        });
        let restored = unsafe {
            let mut now: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGHUP, std::ptr::null(), &mut now);
            now.sa_sigaction
        };
        assert_ne!(
            restored, defer as extern "C" fn(libc::c_int) as usize,
            "the handler outlived the guard"
        );
    }
}
