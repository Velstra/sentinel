//! Secret prompts switch terminal echo off before publishing the prompt.

use std::io::{BufRead, Write};
use std::os::fd::RawFd;

use anyhow::{Context, Result};

pub fn prompt(message: &str) -> Result<String> {
    read_secret(
        message,
        libc::STDIN_FILENO,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )
}

fn read_secret(
    message: &str,
    input_fd: RawFd,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<String> {
    // A fast paste or an automated console can answer the first visible byte.
    // Echo must already be disabled when any part of the prompt is published.
    let mut echo = EchoGuard::quiet(input_fd)?;
    writer
        .write_all(message.as_bytes())
        .context("writing secret prompt")?;
    writer.flush().context("flushing secret prompt")?;
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("reading secret input")?;
    if let Some(guard) = &mut echo {
        writer.write_all(b"\n").context("finishing secret prompt")?;
        writer.flush().context("flushing secret prompt")?;
        guard.restore().context("restoring terminal settings")?;
    }
    Ok(line)
}

struct EchoGuard {
    fd: RawFd,
    original: Option<libc::termios>,
}

impl EchoGuard {
    fn quiet(fd: RawFd) -> Result<Option<Self>> {
        // SAFETY: termios contains integer fields and arrays; zero is valid.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        loop {
            // SAFETY: original is writable and its pointer outlives the call.
            if unsafe { libc::tcgetattr(fd, &mut original) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // Pipes and answer files have no terminal echo. Other observation
            // failures must not silently permit visible password entry.
            if error.raw_os_error() == Some(libc::ENOTTY) {
                return Ok(None);
            }
            return Err(error).context("reading terminal settings before secret input");
        }
        let guard = Self {
            fd,
            original: Some(original),
        };
        let mut quiet = original;
        quiet.c_lflag &= !(libc::ECHO | libc::ECHONL);
        set_terminal(fd, &quiet).context("disabling terminal echo for secret input")?;
        Ok(Some(guard))
    }

    fn restore(&mut self) -> std::io::Result<()> {
        if let Some(original) = &self.original {
            set_terminal(self.fd, original)?;
            self.original = None;
        }
        Ok(())
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        // Also restores on read/write errors and unwinding. An explicit failed
        // restoration remains armed so this final attempt still runs.
        let _ = self.restore();
    }
}

fn set_terminal(fd: RawFd, settings: &libc::termios) -> std::io::Result<()> {
    loop {
        // SAFETY: settings is initialized and remains valid for this call.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, settings) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{BufReader, Read};
    use std::os::fd::{AsRawFd, FromRawFd};

    fn pty() -> (File, File) {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: both output pointers are valid; optional settings are null.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: openpty returned distinct descriptors owned by this function.
        unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) }
    }

    fn flags(fd: RawFd) -> libc::tcflag_t {
        // SAFETY: zero is valid for termios; the call fills initialized storage.
        let mut settings = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(fd, &mut settings) }, 0);
        settings.c_lflag
    }

    struct ImmediateAnswer {
        terminal: File,
        master: File,
        answered: bool,
        fail_flush: bool,
    }

    impl Write for ImmediateAnswer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            assert_eq!(
                flags(self.terminal.as_raw_fd()) & (libc::ECHO | libc::ECHONL),
                0,
                "the prompt became visible while echo was enabled"
            );
            self.terminal.write_all(bytes)?;
            if !self.answered {
                self.master.write_all(b"private-fixture-password\n")?;
                self.answered = true;
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if self.fail_flush {
                Err(std::io::Error::other("fixture flush failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn a_real_pty_hides_an_answer_sent_at_the_first_prompt_byte() {
        let (mut master, terminal) = pty();
        let original = flags(terminal.as_raw_fd());
        assert_ne!(original & libc::ECHO, 0);
        let mut reader = BufReader::new(terminal.try_clone().unwrap());
        let mut writer = ImmediateAnswer {
            terminal: terminal.try_clone().unwrap(),
            master: master.try_clone().unwrap(),
            answered: false,
            fail_flush: false,
        };
        assert_eq!(
            read_secret("Secret: ", terminal.as_raw_fd(), &mut reader, &mut writer).unwrap(),
            "private-fixture-password\n"
        );
        assert_eq!(flags(terminal.as_raw_fd()), original);
        // SAFETY: the master descriptor is valid and O_NONBLOCK is a legal flag.
        assert_eq!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let mut visible = [0; 1024];
        let n = master.read(&mut visible).unwrap();
        let visible = String::from_utf8_lossy(&visible[..n]);
        assert!(visible.contains("Secret: "));
        assert!(!visible.contains("private-fixture-password"));
    }

    #[test]
    fn a_prompt_write_failure_restores_the_real_terminal() {
        let (master, terminal) = pty();
        let original = flags(terminal.as_raw_fd());
        let mut writer = ImmediateAnswer {
            terminal: terminal.try_clone().unwrap(),
            master,
            answered: false,
            fail_flush: true,
        };
        let result = read_secret(
            "Secret: ",
            terminal.as_raw_fd(),
            &mut std::io::Cursor::new(b"unused\n"),
            &mut writer,
        );
        assert!(result.is_err());
        assert_eq!(flags(terminal.as_raw_fd()), original);
    }

    #[test]
    fn a_bad_input_descriptor_refuses_before_publishing_the_prompt() {
        let mut output = Vec::new();
        assert!(
            read_secret(
                "Secret: ",
                -1,
                &mut std::io::Cursor::new(b"secret\n"),
                &mut output
            )
            .is_err()
        );
        assert!(output.is_empty());
    }
}
