//! Console adapter for the same durable worker used by the management API.
//! No console-owned writer, source override or automatic reboot exists.
use std::time::{Duration, Instant};

use anyhow::{Result, bail, ensure};
use clap::Subcommand;

use crate::update_jobs::{self, Action, Code, JobView, Request, Status};

#[derive(Subcommand)]
pub enum SystemCommand {
    /// Show the current slot, boot assessment, verified offer and durable jobs as JSON.
    Status,
    /// Check or stage using the saved channel and pinned signing identity.
    Update {
        #[command(subcommand)]
        command: UpdateCommand,
    },
}

#[derive(Subcommand)]
pub enum UpdateCommand {
    /// Verify a signed offer. Returns the durable job immediately unless --wait.
    Check {
        #[arg(long)]
        wait: bool,
    },
    /// Stage exactly the offer previously reviewed in status/check output; no reboot.
    #[command(visible_alias = "apply")]
    Stage {
        /// Exact 64-character offer ID, not a version or URL.
        #[arg(long)]
        offer: String,
        #[arg(long)]
        wait: bool,
    },
    /// Observe an existing retained job, including after a console disconnect.
    Job {
        id: String,
        #[arg(long)]
        wait: bool,
    },
}

fn status() -> Result<Status> {
    update_jobs::status(crate::saved_config_path().as_path(), true, true).map_err(Into::into)
}

fn request(status: &Status, action: Action, offer: Option<String>) -> Result<Request> {
    if let Some(code) = status.unavailable {
        bail!(code.message());
    }
    ensure!(
        match action {
            Action::Check => status.can_check,
            Action::Stage => status.can_stage,
        },
        "{}",
        Code::Conflict.message()
    );
    if action == Action::Stage {
        ensure!(
            status.offer.as_ref().map(|o| &o.id) == offer.as_ref(),
            "{}",
            Code::Conflict.message()
        );
    }
    let mut random = [0u8; 32];
    getrandom::getrandom(&mut random).map_err(|_| update_jobs::Error(Code::StateUnavailable))?;
    let value = Request {
        request_id: random.iter().map(|b| format!("{b:02x}")).collect(),
        expected_generation: status
            .generation
            .clone()
            .ok_or(update_jobs::Error(Code::StateUnavailable))?,
        expected: status
            .mutation_context
            .clone()
            .ok_or(update_jobs::Error(Code::StateUnavailable))?,
        offer_id: offer,
    };
    update_jobs::validate_request(action, &value)?;
    Ok(value)
}

fn print_job(job: &JobView) -> Result<()> {
    println!("{}", serde_json::to_string(job)?);
    Ok(())
}

fn observe(id: &str, wait: bool) -> Result<()> {
    ensure!(
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "Invalid job ID."
    );
    // This bounds only console observation, never the independent worker.
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let state = status()?;
        let job = state
            .jobs
            .iter()
            .find(|j| j.id == id)
            .ok_or(update_jobs::Error(Code::NotFound))?;
        if !wait || job.phase.terminal() {
            print_job(job)?;
            if let Some(error) = job.error {
                bail!(error.message());
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            print_job(job)?;
            bail!(
                "Observation timed out; the independent worker was NOT cancelled. Use `sudo sentinel system update job {id}`; do not resubmit."
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

pub fn run(command: SystemCommand) -> Result<()> {
    let command = match command {
        SystemCommand::Status => {
            println!("{}", serde_json::to_string_pretty(&status()?)?);
            return Ok(());
        }
        SystemCommand::Update { command } => command,
    };
    let (action, offer, wait) = match command {
        UpdateCommand::Check { wait } => (Action::Check, None, wait),
        UpdateCommand::Stage { offer, wait } => (Action::Stage, Some(offer), wait),
        UpdateCommand::Job { id, wait } => return observe(&id, wait),
    };
    let request = request(&status()?, action, offer)?;
    // Print the correlation before admission. If launch/admission readback is
    // uncertain, status can find this request without a second mutation.
    eprintln!(
        "Update request {}. If interrupted, inspect `sudo sentinel system status`; never blindly retry.",
        request.request_id
    );
    let job = update_jobs::submit(crate::saved_config_path().as_path(), true, action, &request)?;
    print_job(&job)?;
    if wait {
        observe(&job.id, true)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn operational_grammar_has_no_reboot_source_or_trust_bypass() {
        for args in [
            vec!["sentinel", "system", "status"],
            vec!["sentinel", "system", "update", "check", "--wait"],
            vec![
                "sentinel",
                "system",
                "update",
                "stage",
                "--offer",
                &"a".repeat(64),
            ],
            vec![
                "sentinel",
                "system",
                "update",
                "apply",
                "--offer",
                &"a".repeat(64),
            ],
        ] {
            assert!(crate::Cli::try_parse_from(args).is_ok());
        }
        for flag in [
            "--reboot",
            "--allow-downgrade",
            "--allow-unsigned",
            "--source",
            "--pubkey",
        ] {
            assert!(
                crate::Cli::try_parse_from([
                    "sentinel",
                    "system",
                    "update",
                    "stage",
                    "--offer",
                    &"a".repeat(64),
                    flag
                ])
                .is_err()
            );
        }
        assert!(crate::Cli::try_parse_from(["sentinel", "system", "update", "stage"]).is_err());
    }

    #[test]
    fn unavailable_context_never_creates_an_update_request() {
        let state = update_jobs::unavailable_status(Code::UnsupportedRuntime);
        assert!(request(&state, Action::Check, None).is_err());
        assert!(request(&state, Action::Stage, Some("a".repeat(64))).is_err());
    }
}
