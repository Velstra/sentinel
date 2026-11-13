//! Private, bounded Prepared/Go protocol for the immutable Enterprise provider.
//! Credentials are written only to an anonymous stdin pipe. In particular,
//! neither raw provider errors nor stdout are suitable for management responses.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Result, bail, ensure};
use serde::Deserialize;

use crate::{install, update};

const MAX_RESPONSE: usize = 4096;
const MAX_REQUEST: usize = 32768;
const IPC: Duration = Duration::from_secs(28);
const TOTAL: Duration = Duration::from_secs(8 * 60 * 60);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireManifest {
    version: String,
    image: String,
    sha256: String,
    product: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOffer {
    manifest: WireManifest,
    manifest_sha256: String,
    public_key_sha256: String,
}
impl WireOffer {
    fn matches(&self, expected: &update::VerifiedOffer) -> bool {
        self.manifest.version == expected.manifest.version
            && self.manifest.image == expected.manifest.image
            && self.manifest.sha256 == expected.manifest.sha256
            && Some(self.manifest.product.as_str()) == expected.manifest.product.as_deref()
            && self.manifest_sha256 == expected.manifest_sha256
            && self.public_key_sha256 == expected.public_key_sha256
    }
}

#[derive(Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
enum Frame {
    Phase {
        schema: u32,
        phase: install::UpdatePhase,
    },
    Prepared {
        schema: u32,
        token: String,
        offer: WireOffer,
    },
    Complete {
        schema: u32,
        staged: install::StagedImage,
    },
    Error {
        schema: u32,
        code: String,
    },
}

/// Keep the leader unreaped until its process group is done, so PID reuse can
/// never turn cleanup into a signal for an unrelated process group.
struct OwnedChild {
    child: Child,
    admitted: bool,
    reaped: bool,
    deadline: Instant,
}
impl OwnedChild {
    fn exited(&self) -> Result<bool> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let status = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if status != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                return Ok(false);
            }
            bail!("native provider child ownership unavailable");
        }
        Ok(unsafe { info.si_pid() } != 0)
    }

    fn group_writing(&self) -> Result<bool> {
        // A killed helper can leave the actual sysupdate writer alive. The
        // immutable helper does not change process groups; do not kill that
        // admitted writer just because its Python parent died. Linux /proc is
        // required here, as it already is for the appliance's boot identity.
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            if !entry
                .file_name()
                .as_encoded_bytes()
                .iter()
                .all(u8::is_ascii_digit)
            {
                continue;
            }
            let text = match std::fs::read(entry.path().join("stat")) {
                Ok(text) => text,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => bail!("native provider process-group observation unavailable"),
            };
            if live_group_member(&text, self.child.id()) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn settle(&mut self, pipe: &mut impl Read) -> Result<bool> {
        // Closing stdin tells Prepared to refuse and unwind its persistent
        // TemporaryDirectory. Do not immediately SIGKILL normal pre-Go CAS
        // refusals and leak the entire downloaded bundle on persistent state.
        let cleanup_deadline = (Instant::now() + IPC).min(self.deadline);
        let mut stopped = false;
        loop {
            if !self.admitted && !stopped && Instant::now() >= cleanup_deadline {
                unsafe {
                    libc::kill(-(self.child.id() as i32), libc::SIGKILL);
                }
                stopped = true;
            }
            // Drain even after a malformed result: a noisy pipe must not block
            // an admitted writer while the worker waits for its real exit.
            let mut buffer = [0; 4096];
            for _ in 0..16 {
                match pipe.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
            if self.exited()? && (!self.admitted || self.group_writing().is_ok_and(|live| !live)) {
                let status = self.child.wait()?;
                self.reaped = true;
                return Ok(status.success());
            }
            ensure!(
                Instant::now() < self.deadline,
                "native provider exit deadline exceeded"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped && !self.admitted {
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
            let _ = self.child.wait();
        }
        // After Go, only settle() waits for the writer. The outer systemd
        // service owns the hard runtime deadline and the entire cgroup. Never
        // add an error-path kill/retry here or release another process's flock.
    }
}

fn live_group_member(stat: &[u8], group: u32) -> bool {
    // Linux task comm is not necessarily UTF-8. Decode only the numeric tail;
    // an unrelated process name must not stall every admitted update.
    let Some(end) = stat.windows(2).rposition(|pair| pair == b") ") else {
        return false;
    };
    let Ok(tail) = std::str::from_utf8(&stat[end + 2..]) else {
        return false;
    };
    let mut fields = tail.split_whitespace();
    let state = fields.next();
    let _parent = fields.next();
    let actual = fields.next().and_then(|s| s.parse::<u32>().ok());
    actual == Some(group) && !matches!(state, Some("Z" | "X"))
}

fn nonblocking(fd: libc::c_int) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
        "native provider pipe setup failed"
    );
    Ok(())
}

fn send(writer: &mut impl Write, bytes: &[u8], deadline: Instant) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        ensure!(
            Instant::now() < deadline,
            "native provider input deadline exceeded"
        );
        match writer.write(&bytes[offset..]) {
            Ok(0) => bail!("native provider input closed"),
            Ok(count) => offset += count,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(_) => bail!("native provider input failed"),
        }
    }
    Ok(())
}

fn receive(reader: &mut impl Read, pending: &mut Vec<u8>, deadline: Instant) -> Result<Frame> {
    loop {
        if let Some(end) = pending.iter().position(|b| *b == b'\n') {
            let frame = serde_json::from_slice(&pending[..end])
                .map_err(|_| anyhow::anyhow!("invalid native provider frame"));
            pending.drain(..=end);
            return frame;
        }
        ensure!(
            pending.len() < MAX_RESPONSE,
            "oversized native provider frame"
        );
        ensure!(
            Instant::now() < deadline,
            "native provider response deadline exceeded"
        );
        let mut buffer = [0; 1024];
        let available = (MAX_RESPONSE - pending.len()).min(buffer.len());
        match reader.read(&mut buffer[..available]) {
            Ok(0) => bail!("native provider closed without a complete result"),
            Ok(n) => pending.extend_from_slice(&buffer[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(_) => bail!("native provider response failed"),
        }
    }
}

pub(super) fn run(
    command: Command,
    channel: &crate::config::UpdateChannel,
    expected: &update::VerifiedOffer,
    hooks: install::UpdateHooks<'_>,
) -> Result<install::StagedImage> {
    run_with_deadlines(command, channel, expected, hooks, TOTAL, IPC)
}

fn run_with_deadlines(
    mut command: Command,
    channel: &crate::config::UpdateChannel,
    expected: &update::VerifiedOffer,
    hooks: install::UpdateHooks<'_>,
    total: Duration,
    ipc: Duration,
) -> Result<install::StagedImage> {
    // An ignored SIGCHLD/external reaper invalidates PID ownership. Refuse
    // before spawning, rather than later signal a recycled group identifier.
    let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition) } == 0
            && disposition.sa_sigaction == libc::SIG_DFL
            && disposition.sa_flags & libc::SA_NOCLDWAIT == 0,
        "native provider cannot own its child"
    );
    ensure!(
        crate::boot_entry::native_version(&expected.manifest.version)
            && expected.manifest.product.as_deref() == Some(update::PRODUCT),
        "ineligible native offer"
    );
    let mut request = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "channel": {"url": channel.url, "public-key": channel.public_key,
                    "subscription-key": channel.subscription_key},
        "expected": expected,
    }))?;
    request.push(b'\n');
    ensure!(
        request.len() <= MAX_REQUEST,
        "native provider request is oversized"
    );
    let deadline = Instant::now() + total;
    let child = command
        .process_group(0)
        .env_clear()
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| anyhow::anyhow!("native provider could not start"))?;
    let mut child = OwnedChild {
        child,
        admitted: false,
        reaped: false,
        deadline,
    };
    let mut input = child
        .child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("native provider input unavailable"))?;
    let mut output = child
        .child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("native provider output unavailable"))?;
    nonblocking(input.as_raw_fd())?;
    nonblocking(output.as_raw_fd())?;
    let mut pending = Vec::new();
    // A panic in an internal journal/CAS hook must not unwind across an admitted
    // writer's owner and cause the surrounding systemd unit to kill its cgroup.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        send(&mut input, &request, (Instant::now() + ipc).min(deadline))?;
        // Do not retain an additional credential payload through the write.
        request.fill(0);
        let phases = [
            install::UpdatePhase::Metadata,
            install::UpdatePhase::Downloading,
            install::UpdatePhase::Verifying,
            install::UpdatePhase::Preflight,
        ];
        for wanted in phases {
            match receive(&mut output, &mut pending, deadline)? {
                Frame::Phase { schema: 1, phase } if phase == wanted => (hooks.phase)(phase)?,
                _ => bail!("native provider refused or violated prewrite ordering"),
            }
        }
        let prepared_at = Instant::now();
        let token = match receive(&mut output, &mut pending, deadline)? {
            Frame::Prepared {
                schema: 1,
                token,
                offer,
            } if offer.matches(expected) && crate::update_jobs::is_id(&token) => token,
            _ => bail!("native provider prepared a different or invalid offer"),
        };
        (hooks.before_write)()?;
        ensure!(
            !child.exited()? && prepared_at.elapsed() < ipc,
            "native provider preparation expired"
        );
        // The hook must durably publish Writing before any byte of Go. A lost
        // write/response after this boundary must remain outcome-unknown.
        (hooks.phase)(install::UpdatePhase::Writing)?;
        ensure!(
            prepared_at.elapsed() < ipc,
            "native provider authorization expired"
        );
        let permission =
            serde_json::to_vec(&serde_json::json!({"schema":1,"event":"go","token":token}))?;
        child.admitted = true;
        let mut permission = permission;
        permission.push(b'\n');
        send(&mut input, &permission, (prepared_at + ipc).min(deadline))?;
        // EOF prevents another permission request or credential reuse.
        drop(input);
        match receive(&mut output, &mut pending, deadline)? {
            Frame::Phase {
                schema: 1,
                phase: install::UpdatePhase::Writing,
            } => {}
            _ => bail!("native provider did not acknowledge the write boundary"),
        }
        match receive(&mut output, &mut pending, deadline)? {
            Frame::Phase {
                schema: 1,
                phase: install::UpdatePhase::Publishing,
            } => (hooks.phase)(install::UpdatePhase::Publishing)?,
            _ => bail!("native provider did not confirm publication"),
        }
        match receive(&mut output, &mut pending, deadline)? {
            Frame::Complete { schema: 1, staged } => Ok(staged),
            Frame::Error { schema, code } => {
                // Validate, but never echo, even a supposedly safe error frame.
                let _known =
                    schema == 1 && matches!(code.as_str(), "refused" | "write-outcome-unknown");
                bail!("native provider did not confirm a complete write")
            }
            _ => bail!("native provider returned no valid completion"),
        }
    }))
    .unwrap_or_else(|_| Err(anyhow::anyhow!("native provider owner hook interrupted")));
    request.fill(0);
    // Reject extra data, including a second terminal frame. Keep draining on
    // failures without killing a writer that already received Go.
    let mut extra = !pending.is_empty();
    if result.is_ok() {
        loop {
            let mut bytes = [0; 1024];
            match output.read(&mut bytes) {
                Ok(0) => break,
                Ok(_) => extra = true,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => {
                    extra = true;
                    break;
                }
            }
            if Instant::now() >= deadline {
                extra = true;
                break;
            }
        }
    }
    let settled = child.settle(&mut output);
    match result {
        // Preserve the typed CAS/journal refusal after waiting for cleanup.
        // A nonzero refusal exit must not replace Conflict with StageRefused.
        Err(error) => Err(error),
        Ok(staged) => {
            ensure!(
                settled? && !extra,
                "native provider exit or trailing data invalidated the result"
            );
            Ok(staged)
        }
    }
}

#[cfg(test)]
mod tests;
