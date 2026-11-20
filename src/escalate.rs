//! One privilege escalation for an operator's configuration session.
//!
//! An operator account on the appliance is in `wheel`, and `wheel` has
//! passwordless sudo for everything (`security.sudo.wheelNeedsPassword =
//! false`). A `configure` session it opens therefore applies a commit as root
//! either way. Doing so one `sudo` per privileged step cost a sudo round trip
//! each: an unchanged commit of a two-zone box made 76 of them and took ~27 s
//! instead of the ~4 s the same commit takes as root
//! (`checks.commit-latency`).
//!
//! So an on-box session of such an operator re-executes itself once under
//! `sudo`, as `ha pair` already does. This grants nothing new: the policy
//! decides, exactly as it did for each step, and sudo's log now records one
//! `configure` by the operator instead of 76 anonymous-looking file installs.
//! An account outside wheel, an off-box edit and a custom configuration file
//! keep the per-step path unchanged.

use std::ffi::OsString;
use std::path::Path;

/// The argv (after `sudo`) that re-runs this session as root, or `None` when
/// the session must stay as it is.
///
/// `wrapper` is the package's pinned entry point (`SENTINEL_PAIR_SELF_BIN`):
/// it restores the immutable tool pins that sudo's environment reset drops,
/// so the root session resolves the same programs. Only a store path is
/// accepted; anything else means this is not the installed appliance.
pub(crate) fn configure_argv(
    config: &Path,
    no_apply: bool,
    is_root: bool,
    administrator: bool,
    wrapper: Option<&str>,
) -> Option<Vec<OsString>> {
    if no_apply || is_root || !administrator {
        return None;
    }
    if config != Path::new(crate::session::DEFAULT_CONFIG) {
        return None;
    }
    let wrapper =
        wrapper.filter(|w| w.starts_with("/nix/store/") && !w.chars().any(char::is_control))?;
    Some(vec![
        "-n".into(),
        wrapper.into(),
        "configure".into(),
        "--config".into(),
        config.into(),
    ])
}

/// Re-execute an operator's on-box `configure` session as root through one
/// `sudo`. Returns `Ok(())` when the session should continue in this process
/// (not applicable, or the policy does not allow it); on success it does not
/// return.
pub(crate) fn reexec_configure(config: &Path, no_apply: bool) -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let wrapper = std::env::var("SENTINEL_PAIR_SELF_BIN").ok();
    let Some(argv) = configure_argv(
        config,
        no_apply,
        crate::system::is_root(),
        crate::observe::existing_administrator(),
        wrapper.as_deref(),
    ) else {
        return Ok(());
    };
    // Ask the policy first (`sudo -l <command>` exits 0 only when it would
    // run): a refusal leaves the session on the per-step path rather than
    // failing it, and nothing has been read or changed yet.
    let allowed = Command::new("sudo")
        .args(["-n", "-l"])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !allowed {
        return Ok(());
    }
    // The root session gets the umask the boot service and every root-run
    // VM check apply with (022), not the operator's login umask (077 on
    // NixOS), which sudo would otherwise carry into it. Every file Sentinel
    // writes names its own mode; this keeps directories and anything else
    // created on the way the same as on the paths that are tested.
    // SAFETY: umask has no memory effects; this process is about to exec.
    unsafe { libc::umask(0o022) };
    // exec: sudo takes over this process, the terminal and its signals, and
    // its exit status is the session's.
    let error = Command::new("sudo").args(&argv).exec();
    Err(anyhow::Error::new(error).context("re-running the configuration session through sudo"))
}

/// The name a session's prompt shows: the operator who opened it, also when
/// it runs as root through [`reexec_configure`].
pub(crate) fn operator_name(
    user: Option<String>,
    sudo_user: Option<String>,
    is_root: bool,
) -> String {
    let valid = |n: &String| !n.is_empty() && !n.chars().any(char::is_control);
    if is_root && let Some(name) = sudo_user.filter(valid) {
        return name;
    }
    user.filter(valid).unwrap_or_else(|| "admin".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::DEFAULT_CONFIG;

    const WRAPPER: &str = "/nix/store/0000-sentinel-1.0.0/bin/sentinel";

    fn argv(
        config: &str,
        no_apply: bool,
        root: bool,
        admin: bool,
        wrapper: Option<&str>,
    ) -> Option<Vec<String>> {
        configure_argv(Path::new(config), no_apply, root, admin, wrapper)
            .map(|v| v.into_iter().map(|a| a.into_string().unwrap()).collect())
    }

    #[test]
    fn an_administrators_on_box_session_escalates_once_through_the_pinned_wrapper() {
        assert_eq!(
            argv(DEFAULT_CONFIG, false, false, true, Some(WRAPPER)).unwrap(),
            ["-n", WRAPPER, "configure", "--config", DEFAULT_CONFIG]
        );
    }

    #[test]
    fn root_off_box_and_non_administrator_sessions_stay_as_they_are() {
        assert_eq!(
            argv(DEFAULT_CONFIG, false, true, true, Some(WRAPPER)),
            None,
            "already root"
        );
        assert_eq!(
            argv(DEFAULT_CONFIG, true, false, true, Some(WRAPPER)),
            None,
            "--no-apply"
        );
        assert_eq!(
            argv(DEFAULT_CONFIG, false, false, false, Some(WRAPPER)),
            None,
            "not in wheel"
        );
        assert_eq!(
            argv("/home/admin/lab.toml", false, false, true, Some(WRAPPER)),
            None,
            "custom file"
        );
    }

    #[test]
    fn only_a_store_path_wrapper_is_trusted_to_restore_the_tool_pins() {
        assert_eq!(argv(DEFAULT_CONFIG, false, false, true, None), None);
        assert_eq!(
            argv(DEFAULT_CONFIG, false, false, true, Some("sentinel")),
            None
        );
        assert_eq!(
            argv(DEFAULT_CONFIG, false, false, true, Some("/tmp/sentinel")),
            None
        );
        assert_eq!(
            argv(
                DEFAULT_CONFIG,
                false,
                false,
                true,
                Some("/nix/store/x\n/bin/sentinel")
            ),
            None
        );
    }

    #[test]
    fn the_prompt_names_the_operator_not_root() {
        assert_eq!(
            operator_name(Some("root".into()), Some("alice".into()), true),
            "alice"
        );
        assert_eq!(
            operator_name(Some("alice".into()), Some("mallory".into()), false),
            "alice"
        );
        assert_eq!(operator_name(Some("root".into()), None, true), "root");
        assert_eq!(operator_name(None, Some("bad\nname".into()), true), "admin");
    }
}
