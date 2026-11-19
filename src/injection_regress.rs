//! Regression tests for the configuration-injection class (audit 8b6181,
//! CTRL-02/03/08/12/13/16/17/18/29).
//!
//! Every case here is a document that reached a root-run daemon's config file
//! through the API document path (`PUT /api/v1/config`, config-sync, fleet,
//! archive rollback), which runs `Appliance::validate()` and nothing else. Each
//! test first proves its clean twin is accepted, so a refusal is the injected
//! value's doing and not a fixture that never validated.

use crate::config::Appliance;

const BASE: &str = "[system]\nhostname = \"edge\"\n";

/// The clean document must validate (else the dirty refusal proves nothing),
/// and the dirty one must not.
fn refused(clean: &str, dirty: &str) {
    if let Err(e) = Appliance::from_toml(clean) {
        panic!("fixture must validate: {e:#}\n{clean}");
    }
    assert!(
        Appliance::from_toml(dirty).is_err(),
        "an injected value was accepted:\n{dirty}"
    );
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

#[test]
fn ctrl03_ssh_loglevel_cannot_add_sshd_directives() {
    let doc = |level: &str| format!("{BASE}[services.ssh]\nloglevel = {}\n", toml_str(level));
    refused(
        &doc("VERBOSE"),
        &doc("INFO\nAuthorizedKeysCommand /bin/sh -c id\nAuthorizedKeysCommandUser root"),
    );
    // The enum the CLI enforced now holds on every path.
    refused(&doc("verbose"), &doc("LOUD"));
}

#[test]
fn ctrl02_ddclient_login_cannot_split_into_options() {
    let doc = |login: &str| {
        format!(
            "{BASE}[services.dyndns]\nhostname = \"home.example.com\"\nlogin = {}\n",
            toml_str(login)
        )
    };
    refused(
        &doc("user@example.com"),
        &doc("user usev4=cmdv4 cmdv4=\"touch /tmp/pwned\""),
    );
    refused(&doc("user"), &doc("user,usev4=cmdv4"));
}

#[test]
fn ctrl13_dhcp_client_options_cannot_add_networkd_sections() {
    let doc = |field: &str, value: &str| {
        format!(
            "{BASE}[[interface]]\nname = \"wan0\"\nzone = \"wan\"\naddress = \"dhcp\"\n\
             [interface.dhcp]\n{field} = {}\n",
            toml_str(value)
        )
    };
    refused(
        &doc("vendor-class-id", "MSFT 5.0"),
        &doc("vendor-class-id", "x\n[Match]\nName=*"),
    );
    refused(
        &doc("user-class", "cpe"),
        &doc("user-class", "y\n[Link]\nActivationPolicy=always-up"),
    );
    refused(
        &doc("host-name", "edge"),
        &doc("host-name", "edge\nActivationPolicy=always-up"),
    );
    // A lone CR is a line break to systemd's parser.
    refused(
        &doc("vendor-class-id", "MSFT 5.0"),
        &doc("vendor-class-id", "x\r[Match]"),
    );
}

#[test]
fn ctrl17_bond_enums_hold_on_the_document_path() {
    let doc = |field: &str, value: &str| {
        format!(
            "{BASE}[[interface]]\nname = \"bond0\"\ntype = \"bond\"\nbond-mode = \"802.3ad\"\n\
             [interface.bond]\n{field} = {}\n",
            toml_str(value)
        )
    };
    refused(
        &doc("hash-policy", "layer3+4"),
        &doc("hash-policy", "layer2\n[NetDev]\nName=x"),
    );
    refused(
        &doc("hash-policy", "layer2+3"),
        &doc("hash-policy", "layer9"),
    );
    refused(
        &doc("lacp-rate", "fast"),
        &doc("lacp-rate", "fast\nMinLinks=9"),
    );
    refused(&doc("lacp-rate", "slow"), &doc("lacp-rate", "sometimes"));
}

#[test]
fn ctrl16_ntp_allow_from_is_a_prefix() {
    let doc = |net: &str| format!("{BASE}[services.ntp]\nallow-from = [{}]\n", toml_str(net));
    refused(&doc("10.0.0.0/8"), &doc("10.0.0.0/8\ncmdallow all"));
    refused(&doc("2001:db8::/32"), &doc("bindcmdaddress 0.0.0.0"));
}

#[test]
fn ctrl12_wifi_ssid_and_passphrase_cannot_add_directives() {
    let doc = |ssid: &str, pass: &str| {
        format!(
            "{BASE}[[interface]]\nname = \"wlan0\"\ntype = \"wireless\"\nzone = \"lan\"\n\
             address = \"10.9.0.1/24\"\n[interface.wireless]\nmode = \"access-point\"\n\
             ssid = {}\ncountry = \"DE\"\n[interface.wireless.wpa]\npassphrase = {}\n",
            toml_str(ssid),
            toml_str(pass)
        )
    };
    refused(
        &doc("velstra", "correct horse battery"),
        &doc("velstra\nctrl_interface=/tmp/x", "correct horse battery"),
    );
    refused(
        &doc("velstra", "12345678\"#"),
        &doc(
            "velstra",
            "12345678\"\n}\npkcs11_engine_path=/e\nnetwork={\nssid=\"y",
        ),
    );
}

#[test]
fn ctrl18_pppoe_server_subscribers_cannot_forge_rows_or_read_files() {
    let doc = |name: &str, password: &str, address: &str| {
        format!(
            "{BASE}[[services.pppoe-server.user]]\nname = {}\npassword = {}\naddress = {}\n",
            toml_str(name),
            toml_str(password),
            toml_str(address)
        )
    };
    let clean = doc("alice", "s3cret!", "10.0.0.5");
    refused(
        &clean,
        &doc("alice\"\t*\t\"x\"\t*\n\"bob", "s3cret!", "10.0.0.5"),
    );
    refused(&clean, &doc("alice", "@/etc/shadow", "10.0.0.5"));
    refused(&clean, &doc("alice", "s3cret!", "*"));
    refused(&clean, &doc("*", "s3cret!", "10.0.0.5"));
    refused(&clean, &doc("alice", "s3\"cret", "10.0.0.5"));
}

#[test]
fn ctrl29_sysctl_key_dns_txt_and_subscription_key() {
    let sysctl = |key: &str| format!("{BASE}[system.sysctl]\n{} = \"1\"\n", toml_str(key));
    refused(
        &sysctl("net.ipv4.tcp_syncookies"),
        &sysctl("net.ipv4.tcp_syncookies\nkernel.core_pattern"),
    );
    refused(
        &sysctl("net.ipv4.tcp_syncookies"),
        &sysctl("net.ipv4.a = 2 b"),
    );

    let txt = |text: &str| {
        format!(
            "{BASE}[services.dns.txt-record]\n\"_x.lan\" = {}\n",
            toml_str(text)
        )
    };
    refused(&txt("v=spf1 -all"), &txt("v=spf1\",\"injected"));

    let key = |k: &str| {
        format!(
            "{BASE}[update]\nchannel = \"sub\"\n[[update.channels]]\nname = \"sub\"\n\
             url = \"https://updates.example.com/sub\"\npublic-key = \"file:/etc/sentinel/k.pem\"\n\
             subscription-key = {}\n",
            toml_str(k)
        )
    };
    refused(
        &key("abc.DEF-123_~+/="),
        &key("abc\nX-Velstra-Machine-ID: forged"),
    );
    refused(&key("abc.DEF-123_~+/="), &key("abc def"));
}

/// CTRL-08: the CLI tokenizer kept a raw CR inside quotes, and systemd reads a
/// lone CR as a line break. Whatever the lexer does, a CR-bearing value must not
/// get through `commit`.
#[test]
fn ctrl08_a_carriage_return_set_through_the_cli_does_not_commit() {
    let with_location = |location: &str| {
        let mut session = crate::session::Session::empty();
        session.set(&["system", "hostname", "edge"])?;
        session.set(&["services", "snmp", "community", "public"])?;
        session.set(&["services", "snmp", "location", location])?;
        session.commit()
    };
    if let Err(e) = with_location("rack 4") {
        panic!("the clean twin must commit: {e:#}");
    }
    // The `set` may already refuse it; if it reaches the draft, commit must.
    assert!(
        with_location("rack\r4").is_err(),
        "a CR-bearing value committed"
    );
}

/// CTRL-08: the generic rule. A control character in a free-text field no
/// per-field check covers is refused too — that is what makes a field added
/// next year safe without anybody remembering to check it.
#[test]
fn ctrl08_any_string_field_refuses_control_characters() {
    let doc = |loc: &str| {
        format!(
            "{BASE}[services.snmp]\ncommunity = \"public\"\nlocation = {}\n",
            toml_str(loc)
        )
    };
    refused(&doc("rack 4"), &doc("rack\u{2028}4"));
    refused(&doc("rack 4"), &doc("rack\u{85}4"));
    refused(&doc("rack 4"), &doc("rack\u{7f}4"));
    refused(&doc("rack 4"), &doc("rack\t4"));
}

/// Boot safety: a configuration that booted before these rules existed must
/// still bring the box up. `config check` (strict) refuses it; the boot-time
/// apply (`load_lenient`) switches off exactly the offending settings, says so,
/// and keeps everything else.
#[test]
fn ctrl08_a_saved_config_from_before_the_rules_boots_with_only_the_offenders_off() {
    let doc = format!(
        "{BASE}[services.ssh]\nport = 2222\nloglevel = {}\n\
         [services.ntp]\nallow-from = [\"10.0.0.0/8\", \"cmdallow all\"]\n\
         [services.dyndns]\nhostname = \"home.example.com\"\nlogin = \"a usev4=cmdv4\"\n\
         [services.snmp]\ncommunity = \"public\"\nlocation = {}\n",
        toml_str("INFO\nAuthorizedKeysCommand /bin/sh -c id"),
        toml_str("rack\n4"),
    );
    let dir = std::env::temp_dir().join(format!(
        "sentinel-ctrl08-boot-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("appliance.toml");
    std::fs::write(&path, &doc).unwrap();

    assert!(
        Appliance::load(&path).is_err(),
        "config check must stay strict"
    );
    let booted = Appliance::load_lenient(&path).expect("the box must come up");
    // The rest of the configuration is intact…
    assert_eq!(booted.system.hostname, "edge");
    assert_eq!(booted.services.ssh.port, Some(2222));
    assert_eq!(booted.services.ntp.allow_from, ["10.0.0.0/8"]);
    assert_eq!(booted.services.snmp.location.as_deref(), Some("rack 4"));
    // …and the offenders are off, not half-applied.
    assert_eq!(booted.services.ssh.loglevel, None);
    assert!(booted.services.dyndns.is_empty(), "dynamic DNS must be off");
    booted
        .validate()
        .expect("what boot applies is itself valid");

    // The same document as JSON takes the same road.
    let json_path = dir.join("appliance.json");
    let json = serde_json::to_string(&toml::from_str::<toml::Value>(&doc).unwrap()).unwrap();
    std::fs::write(&json_path, json).unwrap();
    assert!(Appliance::load(&json_path).is_err());
    let booted = Appliance::load_lenient(&json_path).unwrap();
    assert_eq!(booted.services.ssh.loglevel, None);
    let _ = std::fs::remove_dir_all(&dir);
}
