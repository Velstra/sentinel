//! The guided installer's full-screen front end.
//!
//! This is an *input layer only*. It collects [`Answers`] and hands them back;
//! it does not build a configuration and it does not touch a disk. The caller
//! turns the answers into `set …` lines and replays them through the real
//! command parser, so what the installer produces is judged by exactly the same
//! grammar and the same `validate()` an operator's own `configure` session goes
//! through. Keeping the pretty part ignorant of the configuration model is what
//! stops the two drifting apart.
//!
//! Two things about the console this has to run on, both learned the hard way:
//!
//! * The Linux virtual console has no alternate screen. `EnterAlternateScreen`
//!   is a no-op there, so without an explicit clear the frame is drawn on top
//!   of the boot messages still standing on the screen — which looks like a
//!   broken, half-drawn interface, because that is what it is.
//! * Its font is not a terminal emulator's. Arrows, guillemets, bullets and
//!   dashes are not all in it, so everything drawn here is ASCII apart from the
//!   box-drawing borders, which every console font carries.
//!
//! The terminal is restored by a guard on every path out, including a panic —
//! an installer that leaves a serial console in raw mode with no cursor is
//! worse than one that never started.

use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

use crate::install::{Disk, Raid, human_size};

/// The smallest terminal this can be drawn in. A serial console is 80×24; below
/// that the caller falls back to the line-by-line front end rather than drawing
/// something unreadable.
pub const MIN_COLS: u16 = 80;
pub const MIN_ROWS: u16 = 24;

/// The console's size in characters, asked of every handle that might know.
///
/// `TIOCGWINSZ` is answered per file descriptor, and the installer is started
/// from a login shell whose descriptors need not all be the console — a handle
/// that does not know returns zero, or a stale default, and the frame is then
/// drawn into a corner of a screen that is really much larger. So ask all of
/// them, plus the controlling terminal by name, and believe the largest answer.
pub fn console_size() -> Option<(u16, u16)> {
    fn of(fd: std::os::fd::RawFd) -> Option<(u16, u16)> {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        let ok = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0;
        (ok && ws.ws_col > 0 && ws.ws_row > 0).then_some((ws.ws_col, ws.ws_row))
    }

    use std::os::fd::AsRawFd;
    let mut best: Option<(u16, u16)> = None;
    let mut consider = |got: Option<(u16, u16)>| {
        if let Some(v) = got {
            let area = |(c, r): (u16, u16)| u32::from(c) * u32::from(r);
            if best.is_none_or(|b| area(v) > area(b)) {
                best = Some(v);
            }
        }
    };
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        consider(of(fd));
    }
    if let Ok(tty) = std::fs::File::open("/dev/tty") {
        consider(of(tty.as_raw_fd()));
    }
    best
}

/// One interface as the installer will configure it.
#[derive(Clone)]
pub struct NicPlan {
    pub name: String,
    pub configure: bool,
    pub zone: String,
    pub address: String,
    pub gateway: String,
}

/// Everything the guided installer collects, before any of it is turned into
/// configuration. Disk choices are indices into the list handed to [`run`].
pub struct Answers {
    pub raid: Raid,
    pub picks: Vec<usize>,
    pub keyboard: String,
    pub locale: String,
    pub timezone: String,
    pub hostname: String,
    pub username: String,
    pub password: String,
    pub ssh_key: String,
    /// Encrypt the writable data partition with LUKS2. When set, [`passphrase`]
    /// carries the passphrase the box asks for at each boot (`sentinel unlock`).
    ///
    /// [`passphrase`]: Self::passphrase
    pub encrypt: bool,
    /// The LUKS2 passphrase, meaningful only when [`encrypt`] is set. Never
    /// rendered back on the review screen or echoed while typed — it is the one
    /// answer whose secrecy is the point.
    ///
    /// [`encrypt`]: Self::encrypt
    pub passphrase: String,
    /// Interfaces to bring up. Configuring one is optional: an operator who
    /// only wants the box installed leaves them all off and sets the network up
    /// from the console afterwards.
    pub nics: Vec<NicPlan>,
    /// Permit SSH from the configured interface's zone. The appliance denies
    /// inbound by default, so without this the box comes up installed and
    /// unreachable — which would make configuring an address here pointless.
    pub permit_ssh: bool,
}

// ── suggestion lists ────────────────────────────────────────────────────────
//
// Nobody should have to know that their layout is spelled `de-latin1-nodeadkeys`
// in order to install a firewall. These are offered as a list to pick from;
// typing filters it, and anything typed that matches nothing is still accepted,
// so an answer that is not on the list is never blocked.

const KEYMAPS: &[&str] = &[
    "us",
    "us-acentos",
    "uk",
    "de",
    "de-latin1-nodeadkeys",
    "at",
    "ch-de",
    "fr",
    "fr-latin9",
    "be-latin1",
    "ch-fr",
    "es",
    "it",
    "pt-latin1",
    "br-abnt2",
    "nl",
    "dk-latin1",
    "fi",
    "no",
    "se-lat6",
    "is-latin1",
    "pl",
    "cz-qwertz",
    "sk-qwerty",
    "hu",
    "sl",
    "hr",
    "ro",
    "bg-cp1251",
    "gr",
    "tr",
    "ru",
    "ua",
    "il-heb",
    "jp106",
    "dvorak",
    "colemak",
];

const LOCALES: &[&str] = &[
    "en_US.UTF-8",
    "en_GB.UTF-8",
    "de_DE.UTF-8",
    "de_AT.UTF-8",
    "de_CH.UTF-8",
    "fr_FR.UTF-8",
    "fr_CH.UTF-8",
    "fr_BE.UTF-8",
    "es_ES.UTF-8",
    "it_IT.UTF-8",
    "nl_NL.UTF-8",
    "pt_PT.UTF-8",
    "pt_BR.UTF-8",
    "da_DK.UTF-8",
    "sv_SE.UTF-8",
    "nb_NO.UTF-8",
    "fi_FI.UTF-8",
    "is_IS.UTF-8",
    "pl_PL.UTF-8",
    "cs_CZ.UTF-8",
    "sk_SK.UTF-8",
    "sl_SI.UTF-8",
    "hr_HR.UTF-8",
    "hu_HU.UTF-8",
    "ro_RO.UTF-8",
    "bg_BG.UTF-8",
    "el_GR.UTF-8",
    "tr_TR.UTF-8",
    "ru_RU.UTF-8",
    "uk_UA.UTF-8",
    "he_IL.UTF-8",
    "ja_JP.UTF-8",
    "zh_CN.UTF-8",
    "C.UTF-8",
];

/// Used when the medium carries no zoneinfo to read.
const TIMEZONES: &[&str] = &[
    "UTC",
    "Europe/Berlin",
    "Europe/Vienna",
    "Europe/Zurich",
    "Europe/London",
    "Europe/Dublin",
    "Europe/Paris",
    "Europe/Brussels",
    "Europe/Amsterdam",
    "Europe/Madrid",
    "Europe/Lisbon",
    "Europe/Rome",
    "Europe/Copenhagen",
    "Europe/Stockholm",
    "Europe/Oslo",
    "Europe/Helsinki",
    "Europe/Warsaw",
    "Europe/Prague",
    "Europe/Budapest",
    "Europe/Bucharest",
    "Europe/Sofia",
    "Europe/Athens",
    "Europe/Istanbul",
    "Europe/Kyiv",
    "Europe/Moscow",
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Los_Angeles",
    "America/Toronto",
    "America/Sao_Paulo",
    "Asia/Jerusalem",
    "Asia/Dubai",
    "Asia/Kolkata",
    "Asia/Singapore",
    "Asia/Hong_Kong",
    "Asia/Shanghai",
    "Asia/Tokyo",
    "Australia/Sydney",
    "Pacific/Auckland",
];

/// Every zone the medium actually carries, so the list is the real one rather
/// than a guess at which zones matter. Falls back to [`TIMEZONES`] where there
/// is no zoneinfo to read.
fn zone_suggestions() -> Vec<String> {
    fn walk(dir: &std::path::Path, prefix: &str, out: &mut Vec<String>, depth: usize) {
        if depth > 2 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            // Zones are Capitalised. The lower-case entries at the top level are
            // the metadata and the compatibility trees (`posix`, `right`,
            // `zone.tab`, `localtime`, …), which are not zones.
            if !name.starts_with(|c: char| c.is_ascii_uppercase()) || name.contains('.') {
                continue;
            }
            let path = entry.path();
            let full = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if path.is_dir() {
                walk(&path, &full, out, depth + 1);
            } else {
                out.push(full);
            }
        }
    }

    for root in ["/etc/zoneinfo", "/usr/share/zoneinfo"] {
        let mut out = Vec::new();
        walk(std::path::Path::new(root), "", &mut out, 0);
        if out.len() > 50 {
            out.sort();
            out.dedup();
            out.insert(0, "UTC".into());
            return out;
        }
    }
    TIMEZONES.iter().map(|s| s.to_string()).collect()
}

/// A single text field, optionally backed by a list to pick from.
#[derive(Clone)]
struct Input {
    label: &'static str,
    value: String,
    /// Shown greyed when the field is empty — the wizard's answer if untouched.
    placeholder: &'static str,
    secret: bool,
    /// Offered below the field while it has the focus. Typing filters them.
    suggestions: Vec<String>,
    /// Which suggestion is highlighted, as an index into the *filtered* list.
    highlight: usize,
}

impl Input {
    fn new(label: &'static str, value: &str, placeholder: &'static str) -> Self {
        Self {
            label,
            value: value.to_string(),
            placeholder,
            secret: false,
            suggestions: Vec::new(),
            highlight: 0,
        }
    }

    fn secret(label: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            placeholder: "",
            secret: true,
            suggestions: Vec::new(),
            highlight: 0,
        }
    }

    fn choose_from(mut self, suggestions: Vec<String>) -> Self {
        self.suggestions = suggestions;
        self
    }

    /// The suggestions matching what has been typed so far.
    fn matches(&self) -> Vec<&str> {
        if self.suggestions.is_empty() {
            return Vec::new();
        }
        let needle = self.value.to_ascii_lowercase();
        self.suggestions
            .iter()
            .filter(|s| needle.is_empty() || s.to_ascii_lowercase().contains(&needle))
            .map(|s| s.as_str())
            .collect()
    }

    /// The highlighted suggestion, if the list still has one.
    fn highlighted(&self) -> Option<String> {
        self.matches().get(self.highlight).map(|s| s.to_string())
    }

    /// Take the highlighted suggestion as the value. Called when the focus
    /// leaves the field, so picking one off the list is all that is needed —
    /// nothing has to be typed out in full.
    fn accept_highlight(&mut self) {
        if let Some(pick) = self.highlighted() {
            self.value = pick;
            self.highlight = 0;
        }
    }

    /// The value, or the placeholder when nothing was typed.
    fn effective(&self) -> String {
        if self.value.is_empty() {
            self.placeholder.to_string()
        } else {
            self.value.clone()
        }
    }
}

/// The pages, in the order they are asked. Where to install comes before what
/// the box will be, so that changing your mind during the questions has erased
/// nothing yet.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Target,
    Locale,
    Encryption,
    Account,
    Network,
    Review,
}

impl Page {
    // Encryption sits after Locale on purpose: the passphrase is typed here, and
    // the keyboard chosen on the previous page is already live on the console —
    // a passphrase entered on the wrong layout is a box that cannot be unlocked.
    const ORDER: [Page; 6] = [
        Page::Target,
        Page::Locale,
        Page::Encryption,
        Page::Account,
        Page::Network,
        Page::Review,
    ];

    fn index(self) -> usize {
        Self::ORDER.iter().position(|p| *p == self).unwrap_or(0)
    }

    fn title(self) -> &'static str {
        match self {
            Page::Target => "Installation target",
            Page::Locale => "Console and locale",
            Page::Encryption => "Disk encryption",
            Page::Account => "First account",
            Page::Network => "Network (optional)",
            Page::Review => "Review",
        }
    }
}

/// The whole wizard's state.
struct App<'a> {
    disks: &'a [Disk],
    page: Page,
    /// Index of the focused item on the current page. The two buttons in the
    /// footer are the last two positions, so Tab walks fields then buttons.
    focus: usize,
    error: Option<String>,

    // Target
    raid: Raid,
    selected: Vec<bool>,
    disk_cursor: usize,

    // Locale
    keyboard: Input,
    sample: Input,
    locale: Input,
    timezone: Input,

    // Encryption
    /// Whether to lay the data filesystem inside a LUKS2 volume. Off by default:
    /// the passphrase must be typed at every boot (there is no unattended unlock
    /// yet), so it is a choice the operator makes, not one the installer makes
    /// for them.
    encrypt: bool,
    passphrase: Input,
    passphrase_confirm: Input,

    // Account
    hostname: Input,
    username: Input,
    password: Input,
    confirm: Input,
    ssh_key: Input,

    // Network
    nics: Vec<NicPlan>,
    nic_cursor: usize,
    nic_zone: Input,
    nic_address: Input,
    nic_gateway: Input,
    permit_ssh: bool,
    /// The keymap already put on the console, so it is not reloaded per keypress.
    applied_keymap: Option<String>,
    /// Whether that load actually worked — the sample check is only meaningful
    /// when it did, and saying so beats letting an operator mistrust their own
    /// typing.
    keymap_live: bool,
}

const RAID_CHOICES: [(Raid, &str, &str); 4] = [
    (Raid::None, "Single disk", "one disk, no array"),
    (
        Raid::Stripe,
        "RAID0",
        "stripe - capacity, no redundancy, 2+ disks",
    ),
    (Raid::Mirror, "RAID1", "mirror - redundancy, 2+ disks"),
    (Raid::Mirror10, "RAID10", "striped mirror, 4+ disks"),
];

fn owned(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

impl<'a> App<'a> {
    fn new(disks: &'a [Disk], nic_names: &[String]) -> Self {
        Self {
            disks,
            page: Page::Target,
            focus: 0,
            error: None,
            raid: Raid::None,
            selected: vec![false; disks.len()],
            disk_cursor: 0,
            keyboard: Input::new("Console keyboard layout", "", "us").choose_from(owned(KEYMAPS)),
            sample: Input::new("Type hello-123 to check", "", ""),
            locale: Input::new("Locale", "", "en_US.UTF-8").choose_from(owned(LOCALES)),
            timezone: Input::new("Timezone", "", "UTC").choose_from(zone_suggestions()),
            encrypt: false,
            passphrase: Input::secret("Passphrase"),
            passphrase_confirm: Input::secret("Repeat passphrase"),
            hostname: Input::new("Hostname", "", "sentinel"),
            username: Input::new("Username", "", "admin"),
            password: Input::secret("Password"),
            confirm: Input::secret("Repeat password"),
            ssh_key: Input::new("SSH public key", "", "(none)"),
            nics: nic_names
                .iter()
                .map(|name| NicPlan {
                    name: name.clone(),
                    // Off by default: this page is optional, and an installer
                    // should not quietly decide to put an address on an
                    // interface nobody asked about.
                    configure: false,
                    zone: "wan".into(),
                    address: "dhcp".into(),
                    gateway: String::new(),
                })
                .collect(),
            nic_cursor: 0,
            nic_zone: Input::new("Zone", "wan", "wan"),
            nic_address: Input::new("Address or dhcp", "dhcp", "dhcp"),
            nic_gateway: Input::new("Default gateway", "", "(none)"),
            permit_ssh: true,
            applied_keymap: None,
            keymap_live: false,
        }
    }

    /// The text fields on the current page, in focus order.
    fn fields(&mut self) -> Vec<&mut Input> {
        match self.page {
            Page::Target | Page::Review => vec![],
            Page::Locale => vec![
                &mut self.keyboard,
                &mut self.sample,
                &mut self.locale,
                &mut self.timezone,
            ],
            // The passphrase fields exist only while encryption is on — the
            // toggle at slot 0 is all there is when it is off.
            Page::Encryption if self.encrypt => {
                vec![&mut self.passphrase, &mut self.passphrase_confirm]
            }
            Page::Encryption => vec![],
            Page::Account => vec![
                &mut self.hostname,
                &mut self.username,
                &mut self.password,
                &mut self.confirm,
                &mut self.ssh_key,
            ],
            Page::Network => vec![
                &mut self.nic_zone,
                &mut self.nic_address,
                &mut self.nic_gateway,
            ],
        }
    }

    /// How many focus slots come before the fields: the list, on the pages that
    /// have one.
    fn list_slots(&self) -> usize {
        match self.page {
            // Target/Network open on a selectable list; Encryption opens on the
            // on/off toggle, which sits in that same first focus slot (Space
            // flips it, like the list rows).
            Page::Target | Page::Network | Page::Encryption => 1,
            _ => 0,
        }
    }

    /// Focus positions on this page: the list (if any), the fields, the SSH
    /// toggle on the network page, then the two footer buttons.
    fn slots(&mut self) -> usize {
        let extra = usize::from(self.page == Page::Network);
        self.list_slots() + self.fields().len() + extra + 2
    }

    fn on_back_button(&mut self) -> bool {
        self.focus + 2 == self.slots()
    }

    fn on_next_button(&mut self) -> bool {
        self.focus + 1 == self.slots()
    }

    /// The SSH toggle at the foot of the network page.
    fn on_ssh_toggle(&mut self) -> bool {
        self.page == Page::Network && self.focus + 3 == self.slots()
    }

    /// The field the focus is on, if it is on one.
    fn focused_field(&mut self) -> Option<&mut Input> {
        if self.on_back_button() || self.on_next_button() || self.on_ssh_toggle() {
            return None;
        }
        let i = self.focus.checked_sub(self.list_slots())?;
        self.fields().into_iter().nth(i)
    }

    fn focus_on_list(&self) -> bool {
        self.list_slots() == 1 && self.focus == 0
    }

    fn chosen(&self) -> Vec<usize> {
        self.selected
            .iter()
            .enumerate()
            .filter(|(_, on)| **on)
            .map(|(i, _)| i)
            .collect()
    }

    /// Save the per-NIC fields back to the interface they belong to. The three
    /// fields are a view onto whichever row the cursor is on, so they have to be
    /// written back before the cursor moves or the page is left.
    fn store_nic(&mut self) {
        let Some(nic) = self.nics.get_mut(self.nic_cursor) else {
            return;
        };
        nic.zone = self.nic_zone.effective();
        nic.address = self.nic_address.effective();
        nic.gateway = self.nic_gateway.value.clone();
    }

    fn load_nic(&mut self) {
        let Some(nic) = self.nics.get(self.nic_cursor) else {
            return;
        };
        self.nic_zone.value = nic.zone.clone();
        self.nic_address.value = nic.address.clone();
        self.nic_gateway.value = nic.gateway.clone();
    }

    /// Everything wrong with the current page, or nothing.
    fn validate(&mut self) -> Option<String> {
        match self.page {
            Page::Target => {
                let n = self.chosen().len();
                let min = self.raid.min_disks();
                if n < min {
                    return Some(format!(
                        "{} needs at least {min} disk(s); {n} selected. Space toggles a disk.",
                        RAID_CHOICES
                            .iter()
                            .find(|(r, _, _)| *r == self.raid)
                            .map(|(_, n, _)| *n)
                            .unwrap_or("This mode")
                    ));
                }
                // Ask the real planner, on the page where the disks are chosen.
                // It refuses a removable medium and a source-disk collision, and
                // finding that out after the last page would throw away every
                // answer given in between.
                let targets: Vec<String> = self
                    .chosen()
                    .iter()
                    .filter_map(|i| self.disks.get(*i))
                    .map(|d| d.dev_path())
                    .collect();
                if let Err(e) = crate::install::plan_targets(self.disks, &targets, self.raid) {
                    return Some(e.to_string());
                }
                None
            }
            Page::Locale => {
                let typed = self.sample.value.trim().to_string();
                if !typed.is_empty() && typed != "hello-123" {
                    return Some(format!(
                        "that came out as {typed:?} - the layout is not what you expect. \
                         Clear the field to keep it anyway."
                    ));
                }
                None
            }
            // Nothing to check when encryption is off. When it is on, the
            // passphrase must be present and typed the same twice — the install
            // path refuses an empty one, and a mistyped one is a volume nobody
            // can open, so both are caught here before a disk is touched.
            Page::Encryption => {
                if !self.encrypt {
                    return None;
                }
                if self.passphrase.value.is_empty() {
                    return Some("an encrypted install needs a non-empty passphrase".into());
                }
                if self.passphrase.value != self.passphrase_confirm.value {
                    return Some("the two passphrases do not match".into());
                }
                None
            }
            Page::Account => {
                if self.password.value.len() < 8 {
                    return Some("the password must be at least 8 characters".into());
                }
                if self.password.value != self.confirm.value {
                    return Some("the two passwords do not match".into());
                }
                None
            }
            // Nothing is required here: leaving every interface off is a valid
            // answer, and means the network is set up from the console later.
            Page::Network => {
                self.store_nic();
                None
            }
            Page::Review => None,
        }
    }

    fn into_answers(mut self) -> Answers {
        self.store_nic();
        Answers {
            raid: self.raid,
            picks: self.chosen(),
            keyboard: self.keyboard.effective(),
            locale: self.locale.effective(),
            timezone: self.timezone.effective(),
            hostname: self.hostname.effective(),
            username: self.username.effective(),
            password: self.password.value.clone(),
            ssh_key: self.ssh_key.value.clone(),
            // The passphrase only means anything when encryption is on; an
            // off-then-typed-then-off dance must not leak a stale one into the
            // install path.
            encrypt: self.encrypt,
            passphrase: if self.encrypt {
                self.passphrase.value.clone()
            } else {
                String::new()
            },
            nics: self.nics.clone(),
            permit_ssh: self.permit_ssh,
        }
    }
}

/// Put the terminal back the way it was found, on every path out — normal
/// return, error, and panic.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        // The clear matters on a console with no alternate screen: without it
        // the frame stays on the screen under whatever is printed next.
        let _ = execute!(
            std::io::stdout(),
            crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
            crossterm::cursor::MoveTo(0, 0),
            LeaveAlternateScreen,
            crossterm::cursor::Show
        );
    }
}

/// Run the guided installer. `Ok(None)` means the operator left without
/// choosing to install; nothing has been touched in that case.
pub fn run(disks: &[Disk], nic_names: &[String]) -> Result<Option<Answers>> {
    enable_raw_mode().context("putting the console into raw mode")?;
    let _guard = TerminalGuard;
    execute!(std::io::stdout(), EnterAlternateScreen).context("switching screens")?;
    let mut term = Terminal::new(CrosstermBackend::new(std::io::stdout()))
        .context("starting the full-screen installer")?;
    // The Linux virtual console has no alternate screen, so the switch above did
    // nothing there and the boot messages are still on it. Clear explicitly.
    term.clear().context("clearing the console")?;

    let mut app = App::new(disks, nic_names);
    app.load_nic();

    let mut sized: Option<Rect> = None;
    loop {
        // Re-measure every frame. A console that grows after the process starts
        // — the framebuffer taking over from the boot console, say — sends no
        // event this can wait for, and a frame drawn at the old size sits in
        // the corner of a screen that is now much bigger.
        if let Some((cols, rows)) = console_size() {
            let want = Rect::new(0, 0, cols, rows);
            if sized != Some(want) {
                term.resize(want).ok();
                term.clear().ok();
                sized = Some(want);
            }
        }
        term.draw(|f| draw(f, &mut app)).context("drawing")?;

        // Poll rather than block: a console that changes size without sending a
        // resize event still gets redrawn at the right width within a second,
        // instead of staying half-drawn until the next keypress.
        if !event::poll(std::time::Duration::from_secs(1)).context("waiting for input")? {
            continue;
        }
        let key = match event::read().context("reading the keyboard")? {
            Event::Key(k) => k,
            Event::Resize(..) => {
                term.clear().ok();
                continue;
            }
            _ => continue,
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        // Ctrl-C leaves, like everywhere else in the CLI.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Ok(None);
        }

        app.error = None;
        match key.code {
            KeyCode::Tab => next_focus(&mut app, 1),
            KeyCode::BackTab => next_focus(&mut app, -1),
            // In a list, or in a field offering suggestions, the arrows browse
            // it — which is what everyone tries first. Tab is what leaves.
            KeyCode::Down => {
                if !browse(&mut app, 1) {
                    next_focus(&mut app, 1);
                }
            }
            KeyCode::Up => {
                if !browse(&mut app, -1) {
                    next_focus(&mut app, -1);
                }
            }
            KeyCode::Left if app.focus_on_list() && app.page == Page::Target => {
                cycle_raid(&mut app, -1)
            }
            KeyCode::Right if app.focus_on_list() && app.page == Page::Target => {
                cycle_raid(&mut app, 1)
            }
            KeyCode::Char(' ') if app.focus_on_list() => toggle(&mut app),
            KeyCode::Char(' ') if app.on_ssh_toggle() => app.permit_ssh = !app.permit_ssh,
            KeyCode::Esc => {
                if !back(&mut app) {
                    return Ok(None);
                }
            }
            // Enter confirms what is in front of you and moves on to the next
            // thing on the page; the page only turns when there is nothing left
            // on it. Turning the page on every Enter meant that confirming a
            // field and leaving the page were the same keystroke, so choosing
            // an answer and losing the page could not be told apart.
            KeyCode::Enter => {
                if app.on_back_button() {
                    if !back(&mut app) {
                        return Ok(None);
                    }
                } else if app.on_next_button() {
                    if app.page == Page::Review {
                        return Ok(Some(app.into_answers()));
                    }
                    match app.validate() {
                        Some(msg) => app.error = Some(msg),
                        None => forward(&mut app),
                    }
                } else {
                    // Take the highlighted suggestion, then step to the next
                    // field. The last field steps onto the button that turns the
                    // page, so Enter still walks the whole page unaided.
                    leave_field(&mut app);
                    let n = app.slots();
                    // Skip the Back button: Enter should never walk backwards.
                    app.focus = (app.focus + 1).min(n - 1);
                    if app.on_back_button() {
                        app.focus += 1;
                    }
                }
            }
            KeyCode::Backspace => {
                if let Some(f) = app.focused_field() {
                    f.value.pop();
                    f.highlight = 0;
                }
            }
            KeyCode::Char(c) => {
                if let Some(f) = app.focused_field() {
                    f.value.push(c);
                    f.highlight = 0;
                }
            }
            _ => {}
        }
    }
}

/// Called when the focus leaves a field: take the highlighted suggestion, and —
/// for the keyboard — put the layout on the console straight away.
///
/// Without that last part the check below it is theatre: the sample is typed on
/// whatever layout the medium booted with, so it comes out the same whichever
/// layout was chosen and proves nothing. Applying it here is what makes typing
/// `hello-123` an actual test of the answer.
fn leave_field(app: &mut App) {
    let leaving_keyboard = app.page == Page::Locale && app.focus == 0;
    if let Some(f) = app.focused_field() {
        f.accept_highlight();
    }
    if leaving_keyboard {
        let keymap = app.keyboard.effective();
        if app.applied_keymap.as_deref() != Some(keymap.as_str()) {
            // Best-effort: a keymap this medium does not carry must not stop an
            // install, and the operator sees the outcome by typing the sample.
            let ok = crate::system::load_keymap(&keymap).is_ok();
            app.applied_keymap = Some(keymap.clone());
            app.keymap_live = ok;
        }
    }
}

/// Move the focus, taking the highlighted suggestion of the field being left.
fn next_focus(app: &mut App, delta: i32) {
    leave_field(app);
    let n = app.slots() as i32;
    app.focus = ((app.focus as i32 + delta).rem_euclid(n)) as usize;
}

/// Browse a list or a suggestion list. `false` means there is nothing here to
/// browse, and the arrow should move the focus instead.
fn browse(app: &mut App, delta: i32) -> bool {
    if app.focus_on_list() {
        move_cursor(app, delta);
        return true;
    }
    let Some(f) = app.focused_field() else {
        return false;
    };
    let n = f.matches().len() as i32;
    if n == 0 {
        return false;
    }
    f.highlight = ((f.highlight as i32 + delta).rem_euclid(n)) as usize;
    true
}

fn cycle_raid(app: &mut App, delta: i32) {
    let i = RAID_CHOICES
        .iter()
        .position(|(r, _, _)| *r == app.raid)
        .unwrap_or(0) as i32;
    let n = RAID_CHOICES.len() as i32;
    app.raid = RAID_CHOICES[((i + delta).rem_euclid(n)) as usize].0;
}

fn move_cursor(app: &mut App, delta: i32) {
    match app.page {
        Page::Target => {
            let n = app.disks.len() as i32;
            if n > 0 {
                app.disk_cursor = ((app.disk_cursor as i32 + delta).rem_euclid(n)) as usize;
            }
        }
        Page::Network => {
            let n = app.nics.len() as i32;
            if n > 0 {
                app.store_nic();
                app.nic_cursor = ((app.nic_cursor as i32 + delta).rem_euclid(n)) as usize;
                app.load_nic();
            }
        }
        _ => {}
    }
}

fn toggle(app: &mut App) {
    match app.page {
        Page::Target => {
            if let Some(sel) = app.selected.get_mut(app.disk_cursor) {
                *sel = !*sel;
            }
        }
        Page::Network => {
            if let Some(nic) = app.nics.get_mut(app.nic_cursor) {
                nic.configure = !nic.configure;
            }
        }
        Page::Encryption => app.encrypt = !app.encrypt,
        _ => {}
    }
}

/// Move to the next page, resetting the focus so the first field of the new
/// page is where typing lands.
fn forward(app: &mut App) {
    let i = app.page.index();
    if i + 1 < Page::ORDER.len() {
        if app.page == Page::Network {
            app.store_nic();
        }
        app.page = Page::ORDER[i + 1];
        app.focus = 0;
        if app.page == Page::Network {
            app.load_nic();
        }
    }
}

/// Move back a page. `false` means there is no page to go back to, i.e. leaving.
fn back(app: &mut App) -> bool {
    let i = app.page.index();
    if i == 0 {
        return false;
    }
    if app.page == Page::Network {
        app.store_nic();
    }
    app.page = Page::ORDER[i - 1];
    app.focus = 0;
    if app.page == Page::Network {
        app.load_nic();
    }
    true
}

// ── drawing ─────────────────────────────────────────────────────────────────

const ACCENT: Color = Color::Cyan;
const MUTED: Color = Color::DarkGray;

/// The largest the dialog is drawn. Beyond this the screen is not filled with a
/// bigger empty box — the frame is centred instead, the way an installer dialog
/// is. Stretched across a wide console the content sat in the top corner with
/// two thirds of a bordered rectangle below it, which reads as half-drawn.
const MAX_COLS: u16 = 110;
const MAX_ROWS: u16 = 34;

/// The dialog's rectangle: the whole console, or a centred piece of it.
fn dialog(full: Rect) -> Rect {
    let width = full.width.min(MAX_COLS);
    let height = full.height.min(MAX_ROWS);
    Rect {
        x: full.x + (full.width - width) / 2,
        y: full.y + (full.height - height) / 2,
        width,
        height,
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let outer = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Min(0),    // body
        Constraint::Length(1), // error / hint
        Constraint::Length(1), // buttons
    ])
    .split(dialog(f.area()));

    let step = app.page.index() + 1;
    let total = Page::ORDER.len();
    // Two rects, not two paragraphs over one: overlapping renders leave the
    // longer of the two showing through the shorter.
    let head = Layout::horizontal([Constraint::Min(0), Constraint::Length(12)]).split(outer[0]);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " Velstra Sentinel - Installation ",
                Style::new().fg(Color::Black).bg(ACCENT).bold(),
            ),
            Span::raw("  "),
            Span::styled(app.page.title(), Style::new().bold()),
        ])),
        head[0],
    );
    f.render_widget(
        Paragraph::new(format!("Step {step}/{total} ")).alignment(Alignment::Right),
        head[1],
    );

    let body = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(ACCENT));
    let inner = body.inner(outer[1]);
    f.render_widget(body, outer[1]);

    match app.page {
        Page::Target => draw_target(f, inner, app),
        Page::Locale | Page::Account => draw_fields(f, inner, app),
        Page::Encryption => draw_encryption(f, inner, app),
        Page::Network => draw_network(f, inner, app),
        Page::Review => draw_review(f, inner, app),
    }

    let hint = match &app.error {
        Some(e) => Line::from(Span::styled(
            format!(" {e}"),
            Style::new().fg(Color::Black).bg(Color::Red).bold(),
        )),
        None => Line::from(Span::styled(
            " Tab moves | up/down browses | Enter takes the pick, again to continue | \
             Space toggles | Esc goes back",
            Style::new().fg(MUTED),
        )),
    };
    let foot = Layout::horizontal([Constraint::Min(0), Constraint::Length(10)]).split(outer[2]);
    f.render_widget(Paragraph::new(hint), foot[0]);
    // Not decoration: when the frame does not fill the screen this is the one
    // number that says whether the console lied about its size or the drawing
    // is at fault.
    f.render_widget(
        Paragraph::new(Span::styled(
            format!("{}x{} ", f.area().width, f.area().height),
            Style::new().fg(MUTED),
        ))
        .alignment(Alignment::Right),
        foot[1],
    );
    draw_buttons(f, outer[3], app);
}

fn draw_buttons(f: &mut Frame, area: Rect, app: &mut App) {
    let last = app.page == Page::Review;
    let (back_focus, next_focus) = (app.on_back_button(), app.on_next_button());
    let next_label = if last {
        " Erase disks and install "
    } else {
        " Next > "
    };
    let next_style = if last {
        Style::new().fg(Color::White).bg(Color::Red).bold()
    } else {
        Style::new().fg(Color::Black).bg(ACCENT)
    };
    let cols =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);
    f.render_widget(
        Paragraph::new(Span::styled(
            " < Back ",
            button_style(Style::new().fg(Color::Black).bg(Color::Gray), back_focus),
        )),
        cols[0],
    );
    f.render_widget(
        Paragraph::new(Span::styled(
            next_label,
            button_style(next_style, next_focus),
        ))
        .alignment(Alignment::Right),
        cols[1],
    );
}

fn button_style(base: Style, focused: bool) -> Style {
    if focused {
        base.add_modifier(Modifier::REVERSED | Modifier::BOLD)
    } else {
        base
    }
}

fn draw_target(f: &mut Frame, area: Rect, app: &mut App) {
    let rows = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Min(0),
    ])
    .split(area.inner(Margin::new(2, 1)));

    let modes: Vec<Span> = RAID_CHOICES
        .iter()
        .map(|(r, name, _)| {
            let on = *r == app.raid;
            Span::styled(
                format!(" {} {name} ", if on { "(o)" } else { "( )" }),
                if on {
                    Style::new().fg(ACCENT).bold()
                } else {
                    Style::new()
                },
            )
        })
        .collect();
    f.render_widget(Paragraph::new(Line::from(modes)), rows[0]);

    let note = RAID_CHOICES
        .iter()
        .find(|(r, _, _)| *r == app.raid)
        .map(|(_, _, d)| *d)
        .unwrap_or("");
    f.render_widget(
        Paragraph::new(Span::styled(
            format!("  left/right picks the mode | {note}"),
            Style::new().fg(MUTED),
        )),
        rows[1],
    );

    let items: Vec<ListItem> = app
        .disks
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let here = i == app.disk_cursor && app.focus_on_list();
            let model = if d.model.is_empty() {
                "(no model)"
            } else {
                &d.model
            };
            ListItem::new(Line::from(Span::styled(
                format!(
                    "{} {} {:<14} {:>10}  {model}{}",
                    if here { ">" } else { " " },
                    if app.selected[i] { "[x]" } else { "[ ]" },
                    d.dev_path(),
                    human_size(d.size),
                    if d.removable { "  [removable]" } else { "" },
                ),
                if here {
                    Style::new().fg(ACCENT).bold()
                } else {
                    Style::new()
                },
            )))
        })
        .collect();
    let list = if items.is_empty() {
        List::new(vec![ListItem::new("no disks found")])
    } else {
        List::new(items)
    };
    f.render_widget(
        list.block(Block::default().title(" Disks (Space selects) ")),
        rows[2],
    );
}

/// One row per field, then the suggestions for whichever field has the focus.
fn draw_fields(f: &mut Frame, area: Rect, app: &mut App) {
    let inner = area.inner(Margin::new(2, 1));
    let count = app.fields().len() as u16;
    let rows = Layout::vertical([Constraint::Length(count * 2), Constraint::Min(0)]).split(inner);

    let focus = app.focus;
    let rendered = render_rows(app.fields(), focus, 0);
    render_field_rows(f, rows[0], &rendered);
    if app.page == Page::Locale {
        let note = match (app.applied_keymap.is_some(), app.keymap_live) {
            (false, _) => {
                "The layout is put on this console when you leave the field above,                            so the check below types on the layout you picked."
            }
            (true, true) => {
                "The layout is live on this console - type the sample to see                              whether it is the one you want."
            }
            (true, false) => {
                "This medium could not load that layout, so the sample below                               still types on the boot layout."
            }
        };
        // Two rows for the note, the rest for the list. Taking the whole area
        // for the note would remove the suggestion list from the one page that
        // exists to offer it.
        let split = Layout::vertical([Constraint::Length(2), Constraint::Min(0)]).split(rows[1]);
        f.render_widget(
            Paragraph::new(Span::styled(note, Style::new().fg(MUTED))).wrap(Wrap { trim: true }),
            split[0],
        );
        draw_suggestions(f, split[1], app);
        return;
    }
    draw_suggestions(f, rows[1], app);
}

/// The field rows as (label, shown value, is-placeholder, focused).
fn render_rows(
    fields: Vec<&mut Input>,
    focus: usize,
    offset: usize,
) -> Vec<(String, String, bool, bool)> {
    fields
        .into_iter()
        .enumerate()
        .map(|(i, inp)| {
            let shown = if inp.secret {
                "*".repeat(inp.value.chars().count())
            } else if inp.value.is_empty() {
                inp.placeholder.to_string()
            } else {
                inp.value.clone()
            };
            (
                inp.label.to_string(),
                shown,
                inp.value.is_empty() && !inp.secret,
                i + offset == focus,
            )
        })
        .collect()
}

fn render_field_rows(f: &mut Frame, area: Rect, fields: &[(String, String, bool, bool)]) {
    let mut constraints: Vec<Constraint> = fields.iter().map(|_| Constraint::Length(2)).collect();
    constraints.push(Constraint::Min(0));
    let rows = Layout::vertical(constraints).split(area);

    // Sized to the space there is, not to a number that happened to fit on one
    // screen: these rows also have to sit beside the interface list, and the
    // console this runs on may be exactly 80 columns wide. A field whose
    // closing bracket falls off the edge looks like a broken interface.
    let width = area.width as usize;
    let label_w = (width / 3).clamp(12, 30);
    let value_w = width.saturating_sub(label_w + 7).max(8);

    for (i, (label, shown, is_placeholder, focused)) in fields.iter().enumerate() {
        let value_style = if *is_placeholder {
            Style::new().fg(MUTED)
        } else {
            Style::new()
        };
        let box_style = if *focused {
            Style::new().fg(ACCENT).bold()
        } else {
            Style::new().fg(MUTED)
        };
        let label = truncate(label, label_w);
        let shown = truncate(shown, value_w);
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::raw(format!("{label:<label_w$}")),
                Span::styled("[ ", box_style),
                Span::styled(format!("{shown:<value_w$}"), value_style),
                Span::styled(" ]", box_style),
                Span::styled(if *focused { "<" } else { " " }, box_style),
            ])),
            rows[i],
        );
    }
}

/// Cut to `width` columns, counting characters rather than bytes.
fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    s.chars().take(width.saturating_sub(1)).collect::<String>() + "~"
}

/// The list the focused field offers. This is the point of the page: an answer
/// is picked, not remembered and typed.
fn draw_suggestions(f: &mut Frame, area: Rect, app: &mut App) {
    if area.height < 3 {
        return;
    }
    let Some(field) = app.focused_field() else {
        return;
    };
    let label = field.label;
    let matches = field.matches();
    if matches.is_empty() {
        return;
    }
    let highlight = field.highlight;
    let room = area.height.saturating_sub(1) as usize;
    // Keep the highlighted row on screen when the list is longer than the box.
    let first = (highlight + 1).saturating_sub(room);
    let items: Vec<ListItem> = matches
        .iter()
        .enumerate()
        .skip(first)
        .take(room)
        .map(|(i, s)| {
            ListItem::new(Line::from(Span::styled(
                format!("{} {s}", if i == highlight { ">" } else { " " }),
                if i == highlight {
                    Style::new().fg(Color::Black).bg(ACCENT).bold()
                } else {
                    Style::new()
                },
            )))
        })
        .collect();
    let title = format!(
        " {label}: {} to choose from, up/down picks, typing filters ",
        matches.len()
    );
    f.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::new().fg(MUTED))
                .title(Span::styled(title, Style::new().fg(MUTED))),
        ),
        area,
    );
}

/// The encryption page: a single on/off toggle at focus slot 0, an honest note
/// about what it does, and — only while it is on — the passphrase pair.
fn draw_encryption(f: &mut Frame, area: Rect, app: &mut App) {
    let inner = area.inner(Margin::new(2, 1));
    let rows = Layout::vertical([
        Constraint::Length(2), // the toggle
        Constraint::Length(5), // the explanation
        Constraint::Min(0),    // the passphrase pair, when on
    ])
    .split(inner);

    let on_toggle = app.focus_on_list();
    let mark = if app.encrypt { "[x]" } else { "[ ]" };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!(
                    "{} {mark} Encrypt the data partition (LUKS2)",
                    if on_toggle { ">" } else { " " }
                ),
                if on_toggle {
                    Style::new().fg(ACCENT).bold()
                } else {
                    Style::new()
                },
            ),
            Span::styled("   (Space toggles)", Style::new().fg(MUTED)),
        ])),
        rows[0],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            "Only the writable data partition is encrypted; the read-only system store \
             is already integrity-sealed. The box asks for this passphrase at every boot \
             (on the console, or through a waiting remote agent) - there is no unattended \
             unlock yet, so keep it somewhere you can reach when the box restarts.",
            Style::new().fg(MUTED),
        ))
        .wrap(Wrap { trim: true }),
        rows[1],
    );

    if app.encrypt {
        // The list occupies focus slot 0 on this page, so the fields start at 1.
        let focus = app.focus;
        let rendered = render_rows(app.fields(), focus, 1);
        render_field_rows(f, rows[2], &rendered);
    }
}

fn draw_network(f: &mut Frame, area: Rect, app: &mut App) {
    let inner = area.inner(Margin::new(2, 1));
    let rows = Layout::vertical([
        Constraint::Length(3), // the explanation
        Constraint::Length(6), // interfaces + their fields
        Constraint::Length(2), // the SSH toggle
        Constraint::Min(0),    // suggestions
    ])
    .split(inner);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Optional. Configure an interface only if the box should be reachable over \
             SSH right after the reboot; otherwise leave them all off and set the network \
             up from the console.",
            Style::new().fg(MUTED),
        ))
        .wrap(Wrap { trim: true }),
        rows[0],
    );

    // Narrow consoles need the room for the fields more than for the names.
    let names = (rows[1].width / 3).clamp(16, 30);
    let cols = Layout::horizontal([Constraint::Length(names), Constraint::Min(0)]).split(rows[1]);
    let items: Vec<ListItem> = app
        .nics
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let here = i == app.nic_cursor && app.focus_on_list();
            ListItem::new(Line::from(Span::styled(
                format!(
                    "{} {} {}",
                    if here { ">" } else { " " },
                    if n.configure { "[x]" } else { "[ ]" },
                    n.name
                ),
                if here {
                    Style::new().fg(ACCENT).bold()
                } else {
                    Style::new()
                },
            )))
        })
        .collect();
    let list = if items.is_empty() {
        List::new(vec![ListItem::new("no interfaces found")])
    } else {
        List::new(items)
    };
    f.render_widget(
        list.block(Block::default().title(" Interfaces (Space) ")),
        cols[0],
    );

    let focus = app.focus;
    // The list occupies focus slot 0 on this page, so the fields start at 1.
    let rendered = render_rows(app.fields(), focus, 1);
    render_field_rows(f, cols[1], &rendered);

    let on_toggle = app.on_ssh_toggle();
    let ssh = if app.permit_ssh { "[x]" } else { "[ ]" };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!(
                    "{} {ssh} Permit SSH from this interface",
                    if on_toggle { ">" } else { " " }
                ),
                if on_toggle {
                    Style::new().fg(ACCENT).bold()
                } else {
                    Style::new()
                },
            ),
            Span::styled("  (inbound is denied by default)", Style::new().fg(MUTED)),
        ])),
        rows[2],
    );

    draw_suggestions(f, rows[3], app);
}

fn draw_review(f: &mut Frame, area: Rect, app: &mut App) {
    let inner = area.inner(Margin::new(2, 1));
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(Span::styled(
        "These disks will be ERASED:",
        Style::new().fg(Color::Red).bold(),
    )));
    for i in app.chosen() {
        if let Some(d) = app.disks.get(i) {
            lines.push(Line::from(format!(
                "    {}  {}  {}",
                d.dev_path(),
                human_size(d.size),
                if d.model.is_empty() {
                    "(no model)"
                } else {
                    &d.model
                }
            )));
        }
    }
    if let Some(level) = app.raid.mdadm_level() {
        lines.push(Line::from(format!(
            "    data partition as mdadm RAID{level} across them"
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "The installed system will come up as:",
        Style::new().bold(),
    )));
    // The password is deliberately absent: this is on screen at the end of an
    // install, which is exactly where it must not be.
    lines.push(Line::from(format!(
        "    hostname   {}",
        app.hostname.effective()
    )));
    lines.push(Line::from(format!(
        "    keyboard   {}   locale {}   timezone {}",
        app.keyboard.effective(),
        app.locale.effective(),
        app.timezone.effective()
    )));
    // The passphrase itself is deliberately absent — this is on screen at the
    // end of an install, exactly where a secret must not be.
    lines.push(Line::from(Span::styled(
        if app.encrypt {
            "    disk       LUKS2 encrypted - the box asks for the passphrase at each boot"
        } else {
            "    disk       not encrypted"
        },
        if app.encrypt {
            Style::new().fg(ACCENT)
        } else {
            Style::new().fg(MUTED)
        },
    )));
    lines.push(Line::from(format!(
        "    account    {}  (password set, not shown)",
        app.username.effective()
    )));
    lines.push(Line::from(Span::styled(
        if app.ssh_key.value.is_empty() {
            "    SSH        password login enabled - no key was given, so the \
             password is the only way in"
        } else {
            "    SSH        key-only, using the key given above"
        },
        Style::new().fg(MUTED),
    )));
    app.store_nic();
    let configured: Vec<NicPlan> = app.nics.iter().filter(|n| n.configure).cloned().collect();
    if configured.is_empty() {
        lines.push(Line::from(Span::styled(
            "    network    not set here - configure it from the console",
            Style::new().fg(MUTED),
        )));
    }
    for n in &configured {
        let gw = if n.gateway.is_empty() {
            String::new()
        } else {
            format!("  via {}", n.gateway)
        };
        lines.push(Line::from(format!(
            "    {}  zone {}  {}{gw}",
            n.name, n.zone, n.address
        )));
    }
    lines.push(Line::from(""));
    let firewall = if configured.is_empty() || !app.permit_ssh {
        "No firewall policy is set by the installer."
    } else {
        "One firewall rule is added: SSH on port 22 from that zone, nothing else."
    };
    lines.push(Line::from(Span::styled(firewall, Style::new().fg(MUTED))));

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(name: &str, gib: u64) -> Disk {
        Disk {
            name: name.into(),
            size: gib * 1024 * 1024 * 1024,
            model: String::new(),
            removable: false,
        }
    }

    /// A wizard on the encryption page, with the toggle already flipped on.
    fn app_on_encryption(encrypt: bool) -> App<'static> {
        // Leak a tiny disk list so the App can borrow it for the test's lifetime.
        let disks: &'static [Disk] = Box::leak(vec![disk("sda", 100)].into_boxed_slice());
        let mut app = App::new(disks, &[]);
        app.page = Page::Encryption;
        app.encrypt = encrypt;
        app
    }

    #[test]
    fn encryption_off_needs_no_passphrase_and_carries_none() {
        let mut app = app_on_encryption(false);
        assert!(app.validate().is_none(), "an unencrypted install validates");
        let answers = app.into_answers();
        assert!(!answers.encrypt);
        assert!(answers.passphrase.is_empty());
    }

    #[test]
    fn an_empty_passphrase_is_refused_while_encrypting() {
        let mut app = app_on_encryption(true);
        let err = app.validate().expect("an empty passphrase must be refused");
        assert!(err.contains("non-empty"), "{err}");
    }

    #[test]
    fn a_mismatched_passphrase_is_refused() {
        let mut app = app_on_encryption(true);
        app.passphrase.value = "correcthorsebattery".into();
        app.passphrase_confirm.value = "typo".into();
        let err = app.validate().expect("a mismatch must be refused");
        assert!(err.contains("do not match"), "{err}");
    }

    #[test]
    fn a_matching_passphrase_validates_and_reaches_the_answers() {
        let mut app = app_on_encryption(true);
        app.passphrase.value = "correcthorsebattery".into();
        app.passphrase_confirm.value = "correcthorsebattery".into();
        assert!(app.validate().is_none(), "a matching pair validates");
        let answers = app.into_answers();
        assert!(answers.encrypt);
        assert_eq!(answers.passphrase, "correcthorsebattery");
    }

    #[test]
    fn the_passphrase_fields_appear_only_while_encryption_is_on() {
        // Off: the toggle is all there is (one focus slot before the two buttons).
        let mut off = app_on_encryption(false);
        assert_eq!(off.fields().len(), 0);
        assert_eq!(off.slots(), 3); // toggle + Back + Next
        // On: the two passphrase fields join the page.
        let mut on = app_on_encryption(true);
        assert_eq!(on.fields().len(), 2);
        assert_eq!(on.slots(), 5); // toggle + 2 fields + Back + Next
    }

    #[test]
    fn a_passphrase_typed_then_turned_off_does_not_leak() {
        let mut app = app_on_encryption(true);
        app.passphrase.value = "secret-then-abandoned".into();
        app.encrypt = false;
        let answers = app.into_answers();
        assert!(!answers.encrypt);
        assert!(
            answers.passphrase.is_empty(),
            "a stale passphrase must not leak"
        );
    }
}
