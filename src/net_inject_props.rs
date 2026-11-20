//! Property test for the configuration-injection class (audit 8b6181, CTRL-08):
//! arbitrary strings in the string fields that reach a generator verbatim.
//!
//! Two claims, checked on every generated value:
//!
//! 1. **validate ⇒ guard.** If `Appliance::validate` accepts the configuration,
//!    the generator's render-time guard accepts it too — so the guard can never
//!    turn a valid configuration into a failed apply (or a dark box at boot).
//! 2. **guard ⇒ no new line.** If the guard accepts the value, the rendered
//!    file has exactly the lines, sections and directives it has with a benign
//!    placeholder, and the same count of the format's quote/escape characters.
//!    The guard alone — without `validate` — is enough to stop the injection,
//!    which is what makes it defence in depth rather than a second copy.
//!
//! A deterministic generator (xorshift, fixed seed) rather than a fuzzing
//! crate: no new dependency in a fixed-output build, and a failure reproduces.

use super::*;
use crate::config::Appliance;

/// What a value is built from: ordinary characters, every kind of line break
/// and control character, and the metacharacters of the formats rendered.
const ALPHABET: &[char] = &[
    'a', 'Z', '0', '7', '.', '-', '_', '@', '+', '/', ':', ' ', ' ', '\t', '\n', '\r', '\0',
    '\u{0b}', '\u{0c}', '\u{1b}', '\u{7f}', '\u{85}', '\u{2028}', '\u{2029}', '"', '\'', '\\', '#',
    '=', ',', '[', ']', '|', '*', '{', '}', '%', '$', ';', 'é',
];

/// Prefixes that make a generated value *nearly* valid, so the interesting
/// region — a good value with something appended — is actually reached.
const SEEDS: &[&str] = &[
    "",
    "INFO",
    "layer3+4",
    "fast",
    "10.0.0.0/8",
    "user",
    "pass-word",
    "edge",
    "MSFT 5.0",
    "velstra",
];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn value(&mut self) -> String {
        let mut s = SEEDS[self.below(SEEDS.len())].to_string();
        for _ in 0..self.below(10) {
            s.push(ALPHABET[self.below(ALPHABET.len())]);
        }
        s
    }
}

/// Every character a reader of these formats takes as the end of a line.
fn is_line_end(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\0' | '\u{0b}' | '\u{0c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// How a format spells a directive.
#[derive(Clone, Copy)]
enum Syntax {
    /// `[Section]` and `Key=value` (networkd, hostapd, wpa_supplicant,
    /// ddclient, dnsmasq).
    KeyEquals,
    /// `Keyword value…` (sshd, chrony); a quoted first word is a value
    /// (pppd secrets), not a keyword.
    Words,
}

/// The structure of a rendered file: per line, a section header verbatim, the
/// directive's key or keyword — and the number of `metas` characters on it.
fn shape(text: &str, syntax: Syntax, metas: &[char]) -> Vec<(String, usize)> {
    text.split(is_line_end)
        .map(|line| {
            let t = line.trim_start();
            let head = match syntax {
                _ if t.starts_with('[') => t.to_string(),
                Syntax::KeyEquals => match t.split_once('=') {
                    Some((key, _)) => format!("{key}="),
                    None => t.split_whitespace().next().unwrap_or("").to_string(),
                },
                Syntax::Words if t.starts_with('"') => "<quoted>".to_string(),
                Syntax::Words => t.split_whitespace().next().unwrap_or("").to_string(),
            };
            (head, line.chars().filter(|c| metas.contains(c)).count())
        })
        .collect()
}

/// The lines of `got` that `expected` does not have (as a multiset): a new
/// section, a new directive, or a directive whose quoting changed. A line the
/// value made the generator *leave out* is not an injection and is allowed.
fn new_lines(expected: &[(String, usize)], got: &[(String, usize)]) -> Vec<(String, usize)> {
    let mut pool = expected.to_vec();
    let mut added = Vec::new();
    for line in got {
        match pool.iter().position(|l| l == line) {
            Some(i) => {
                pool.swap_remove(i);
            }
            None => added.push(line.clone()),
        }
    }
    added
}

/// One field that reaches a generator verbatim.
struct Target {
    name: &'static str,
    /// A configuration that validates with [`Self::placeholder`] in the field.
    base: &'static str,
    placeholder: &'static str,
    set: fn(&mut Appliance, &str),
    guard: fn(&Appliance) -> Result<()>,
    render: fn(&Appliance) -> String,
    syntax: Syntax,
    /// The format's quote and escape characters, whose count must not change.
    metas: &'static [char],
}

const BASE: &str = "[system]\nhostname = \"edge\"\n";
const WAN: &str = "[system]\nhostname = \"edge\"\n[[interface]]\nname = \"wan0\"\nzone = \"wan\"\n\
                   address = \"dhcp\"\n";
const BOND: &str = "[system]\nhostname = \"edge\"\n[[interface]]\nname = \"bond0\"\n\
                    type = \"bond\"\nbond-mode = \"802.3ad\"\n";
const DYNDNS: &str = "[system]\nhostname = \"edge\"\n[services.dyndns]\n\
                      hostname = \"home.example.com\"\n";
const BNG: &str = "[system]\nhostname = \"edge\"\n[[interface]]\nname = \"lan0\"\nzone = \"lan\"\n\
                   address = \"10.0.0.1/24\"\n[services.pppoe-server]\ninterface = \"lan0\"\n\
                   local-address = \"10.67.0.1\"\npool-start = \"10.67.0.10\"\nac-name = \"bng\"\n\
                   [[services.pppoe-server.user]]\nname = \"alice\"\npassword = \"pw-alice\"\n";
const DNS: &str = "[system]\nhostname = \"edge\"\n[[interface]]\nname = \"lan0\"\nzone = \"lan\"\n\
                   address = \"10.0.0.1/24\"\n[services.dns]\nupstream = [\"9.9.9.9\"]\n\
                   serve-on = [\"lan0\"]\n";
const WIFI: &str = "[system]\nhostname = \"edge\"\n[[interface]]\nname = \"wlan0\"\n\
                    type = \"wireless\"\nzone = \"lan\"\naddress = \"10.9.0.1/24\"\n\
                    [interface.wireless]\nmode = \"access-point\"\nssid = \"velstra\"\n\
                    country = \"DE\"\n[interface.wireless.wpa]\nmode = \"wpa2+wpa3\"\n\
                    passphrase = \"correct horse\"\n";

fn dhcp_unit(a: &Appliance) -> String {
    let i = &a.interfaces[0];
    let tun = LinkTunables {
        dhcp: Some(&i.dhcp),
        ..LinkTunables::default()
    };
    network_unit_body(
        &i.name,
        i.address.as_deref(),
        None,
        &[],
        &[],
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        None,
        &tun,
    )
}

fn wifi(a: &mut Appliance) -> &mut crate::config::Wireless {
    a.interfaces[0]
        .wireless
        .as_mut()
        .expect("fixture has a radio")
}

fn radio_guard(a: &Appliance) -> Result<()> {
    let i = &a.interfaces[0];
    crate::wireless::radio_inputs_safe(&i.name, i.wireless.as_ref().expect("radio"))
}

const TARGETS: &[Target] = &[
    Target {
        name: "services ssh loglevel",
        base: BASE,
        placeholder: "INFO",
        set: |a, v| a.services.ssh.loglevel = Some(v.into()),
        guard: |a| ssh_dropin_safe(&a.services.ssh),
        render: |a| ssh_dropin_body(&a.services.ssh),
        syntax: Syntax::Words,
        metas: &[],
    },
    Target {
        name: "interface dhcp vendor-class-id",
        base: WAN,
        placeholder: "x",
        set: |a, v| a.interfaces[0].dhcp.vendor_class_id = Some(v.into()),
        guard: networkd_inputs_safe,
        render: dhcp_unit,
        syntax: Syntax::KeyEquals,
        metas: &[],
    },
    Target {
        name: "interface dhcp user-class",
        base: WAN,
        placeholder: "x",
        set: |a, v| a.interfaces[0].dhcp.user_class = Some(v.into()),
        guard: networkd_inputs_safe,
        render: dhcp_unit,
        syntax: Syntax::KeyEquals,
        metas: &[],
    },
    Target {
        name: "interface dhcp host-name",
        base: WAN,
        placeholder: "edge",
        set: |a, v| a.interfaces[0].dhcp.host_name = Some(v.into()),
        guard: networkd_inputs_safe,
        render: dhcp_unit,
        syntax: Syntax::KeyEquals,
        metas: &[],
    },
    Target {
        name: "interface bond hash-policy",
        base: BOND,
        placeholder: "layer2",
        set: |a, v| a.interfaces[0].bond.hash_policy = Some(v.into()),
        guard: networkd_inputs_safe,
        render: |a| virtual_l2_netdev_body(&a.interfaces[0]),
        syntax: Syntax::KeyEquals,
        metas: &[],
    },
    Target {
        name: "interface bond lacp-rate",
        base: BOND,
        placeholder: "fast",
        set: |a, v| a.interfaces[0].bond.lacp_rate = Some(v.into()),
        guard: networkd_inputs_safe,
        render: |a| virtual_l2_netdev_body(&a.interfaces[0]),
        syntax: Syntax::KeyEquals,
        metas: &[],
    },
    Target {
        name: "services dyndns login",
        base: DYNDNS,
        placeholder: "user",
        set: |a, v| a.services.dyndns.login = Some(v.into()),
        guard: |a| ddclient_conf_body(&a.services.dyndns).map(|_| ()),
        render: |a| ddclient_conf_body(&a.services.dyndns).unwrap().unwrap(),
        syntax: Syntax::KeyEquals,
        metas: &['\'', '"', '\\', ',', ' '],
    },
    Target {
        name: "services dyndns password",
        base: DYNDNS,
        placeholder: "pw",
        set: |a, v| a.services.dyndns.password = Some(v.into()),
        guard: |a| ddclient_conf_body(&a.services.dyndns).map(|_| ()),
        render: |a| ddclient_conf_body(&a.services.dyndns).unwrap().unwrap(),
        syntax: Syntax::KeyEquals,
        metas: &['\'', '\\'],
    },
    Target {
        name: "services ntp allow-from",
        base: BASE,
        placeholder: "10.0.0.0/8",
        set: |a, v| a.services.ntp.allow_from = vec![v.into()],
        guard: |a| chrony_inputs_safe(&a.services.ntp),
        render: |a| chrony_conf_body(&a.services.ntp, &a.interfaces),
        syntax: Syntax::Words,
        metas: &[' ', '\t'],
    },
    Target {
        name: "services ntp upstream",
        base: BASE,
        placeholder: "pool.example.com",
        set: |a, v| a.services.ntp.upstream = vec![v.into()],
        guard: |a| chrony_inputs_safe(&a.services.ntp),
        render: |a| chrony_conf_body(&a.services.ntp, &a.interfaces),
        syntax: Syntax::Words,
        metas: &[' ', '\t'],
    },
    Target {
        name: "services pppoe-server user name",
        base: BNG,
        placeholder: "alice",
        set: |a, v| a.services.pppoe_server.users[0].name = v.into(),
        guard: |a| ppp_secrets_safe(&a.interfaces, &a.services.pppoe_server),
        render: |a| ppp_secrets_body(&a.interfaces, &a.services.pppoe_server).unwrap(),
        syntax: Syntax::Words,
        metas: &['"', '\\'],
    },
    Target {
        name: "services pppoe-server user password",
        base: BNG,
        placeholder: "pw-alice",
        set: |a, v| a.services.pppoe_server.users[0].password = v.into(),
        guard: |a| ppp_secrets_safe(&a.interfaces, &a.services.pppoe_server),
        render: |a| ppp_secrets_body(&a.interfaces, &a.services.pppoe_server).unwrap(),
        syntax: Syntax::Words,
        metas: &['"', '\\'],
    },
    Target {
        name: "services dns txt-record",
        base: DNS,
        placeholder: "v=spf1 -all",
        set: |a, v| {
            a.services.dns.txt_record = [("_x.lan".to_string(), v.to_string())].into();
        },
        guard: |a| dnsmasq_conf_body(&a.services.dns).map(|_| ()),
        render: |a| {
            dnsmasq_conf_body(&a.services.dns)
                .unwrap()
                .expect("dnsmasq is on")
        },
        syntax: Syntax::KeyEquals,
        metas: &['"', '\\'],
    },
    Target {
        name: "interface wireless ssid (hostapd)",
        base: WIFI,
        placeholder: "velstra",
        set: |a, v| wifi(a).ssid = v.into(),
        guard: radio_guard,
        render: |a| {
            crate::wireless::hostapd_conf("wlan0", a.interfaces[0].wireless.as_ref().unwrap())
        },
        syntax: Syntax::KeyEquals,
        metas: &[],
    },
    Target {
        name: "interface wireless passphrase (hostapd)",
        base: WIFI,
        placeholder: "correct horse",
        set: |a, v| wifi(a).wpa.as_mut().unwrap().passphrase = v.into(),
        guard: radio_guard,
        render: |a| {
            crate::wireless::hostapd_conf("wlan0", a.interfaces[0].wireless.as_ref().unwrap())
        },
        syntax: Syntax::KeyEquals,
        metas: &[],
    },
    Target {
        name: "interface wireless passphrase (wpa_supplicant)",
        base: WIFI,
        placeholder: "correct horse",
        set: |a, v| wifi(a).wpa.as_mut().unwrap().passphrase = v.into(),
        guard: radio_guard,
        render: |a| crate::wireless::supplicant_conf(a.interfaces[0].wireless.as_ref().unwrap()),
        syntax: Syntax::KeyEquals,
        metas: &[],
    },
];

const ROUNDS: usize = 400;

#[test]
fn validate_implies_guard_and_guard_implies_no_new_line_section_or_directive() {
    let mut rng = Rng(0x5eed_0bad_c0de_2026);
    for t in TARGETS {
        let mut base = Appliance::from_toml(t.base)
            .unwrap_or_else(|e| panic!("{}: fixture must validate: {e:#}", t.name));
        (t.set)(&mut base, t.placeholder);
        if let Err(e) = base.validate() {
            panic!("{}: the placeholder must validate: {e:#}", t.name);
        }
        (t.guard)(&base).unwrap_or_else(|e| panic!("{}: placeholder guard: {e:#}", t.name));
        let expected = shape(&(t.render)(&base), t.syntax, t.metas);

        let (mut guarded, mut refused) = (0, 0);
        for _ in 0..ROUNDS {
            let value = rng.value();
            let mut a = base.clone();
            (t.set)(&mut a, &value);
            let guard = (t.guard)(&a);
            if a.validate().is_ok() {
                assert!(
                    guard.is_ok(),
                    "{}: {value:?} validates but the render guard refuses it: {:#}",
                    t.name,
                    guard.unwrap_err()
                );
            }
            match guard {
                Err(_) => refused += 1,
                Ok(()) => {
                    guarded += 1;
                    // Same-length placeholder comparison is not needed: the
                    // shape ignores the value and keeps only the structure.
                    let rendered = (t.render)(&a);
                    let added = new_lines(&expected, &shape(&rendered, t.syntax, t.metas));
                    assert!(
                        added.is_empty(),
                        "{}: {value:?} passed the guard and added {added:?} to the file:\n{rendered}",
                        t.name
                    );
                }
            }
        }
        // Neither half may be vacuous: the generator must reach both sides.
        assert!(
            guarded > 0 && refused > 0,
            "{}: guarded {guarded}, refused {refused}",
            t.name
        );
    }
}
