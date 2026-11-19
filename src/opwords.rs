//! The words of an operational `show` / `clear` request (audit 8b6181, CTRL-28).
//!
//! `GET /api/v1/show/<words…>` and `POST /api/v1/clear/<words…>` hand their
//! percent-decoded URL segments to `sentinel show|clear` as arguments, and some
//! of those words go on into another program's argv (`ip`, `wren`) or into a
//! line of an agent control socket's protocol (`revoke <mac> any`, `unmap
//! <proto> <port> …`). A `%0A` there is a second socket command. So every word
//! is checked twice: once generically on the way in ([`check_all`]), and once
//! for the shape its position needs before it is passed on.

use anyhow::{Result, bail};

/// More words than any `show` path has. A request longer than this is not a
/// view anybody asked for.
const MAX_WORDS: usize = 32;

/// Longer than any interface, address, prefix or protocol name.
const MAX_WORD_LEN: usize = 256;

/// Refuse a request whose words could be anything but words: a control
/// character or a Unicode line separator anywhere, whitespace inside a word
/// (the shell would have split it; a URL-encoded one is smuggling), or an
/// absurd number or length.
pub(crate) fn check_all(words: &[String]) -> Result<()> {
    if words.len() > MAX_WORDS {
        bail!("too many words ({} > {MAX_WORDS})", words.len());
    }
    for (i, word) in words.iter().enumerate() {
        if word.len() > MAX_WORD_LEN {
            bail!("word {} is longer than {MAX_WORD_LEN} characters", i + 1);
        }
        if let Some(c) = word
            .chars()
            .find(|c| crate::textcheck::is_forbidden(*c) || c.is_whitespace())
        {
            bail!(
                "word {} contains U+{:04X}; a word holds no whitespace or control characters",
                i + 1,
                c as u32
            );
        }
    }
    Ok(())
}

/// A word that becomes an `ip` argument (`show interfaces <…>`, `show ip
/// route <proto>`): an interface, address, prefix, keyword or protocol name.
/// Never an option (a leading `-`).
pub(crate) fn ip_word(word: &str) -> Result<&str> {
    let ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '-' | '@');
    if word.is_empty() || word.len() > 64 || word.starts_with('-') || !word.chars().all(ok) {
        bail!("{word:?} is not an interface, address or keyword");
    }
    Ok(word)
}

/// A word that names an interface (`show arp <dev>`).
pub(crate) fn iface_word(word: &str) -> Result<&str> {
    crate::config::validate_iface_name(word)?;
    if word.starts_with('-') {
        bail!("{word:?} is not an interface name");
    }
    Ok(word)
}

/// `clear portal session <mac>`: a hardware address, which is what the portal
/// socket's `revoke` takes.
pub(crate) fn mac_word(word: &str) -> Result<&str> {
    crate::config::validate_mac(word)?;
    Ok(word)
}

/// `clear port-mapping <proto> <port>`.
pub(crate) fn mapping_words<'a>(proto: &'a str, port: &str) -> Result<(&'a str, u16)> {
    if !matches!(proto, "tcp" | "udp") {
        bail!("{proto:?}: tcp | udp");
    }
    let port: u16 = port
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| anyhow::anyhow!("{port:?} is not a port (1-65535)"))?;
    Ok((proto, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(ws: &[&str]) -> Vec<String> {
        ws.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn a_percent_decoded_line_break_never_reaches_a_socket_or_an_argv() {
        for bad in ["aa:bb\nrevoke all", "x\r", "x\0", "a b", "x\u{2028}y"] {
            assert!(
                check_all(&words(&["portal", "session", bad])).is_err(),
                "{bad:?}"
            );
        }
        assert!(check_all(&words(&["interfaces", "eth0"])).is_ok());
        assert!(check_all(&vec!["x".to_string(); MAX_WORDS + 1]).is_err());
    }

    /// The shipped entry points refuse before anything is sent: on the base,
    /// `clear portal session <mac>%0Arevoke all` reached the portal socket.
    #[test]
    fn clear_and_show_refuse_a_smuggled_line_before_sending_it() {
        let smuggled = words(&["portal", "session", "aa:bb:cc:dd:ee:ff any\nrevoke all"]);
        assert!(crate::clear_op(&smuggled).is_err());
        let not_a_mac = words(&["portal", "session", "all"]);
        assert!(crate::clear_op(&not_a_mac).is_err());
        let not_a_port = words(&["port-mapping", "tcp", "1 all"]);
        assert!(crate::clear_op(&not_a_port).is_err());
        assert!(crate::show_op(&words(&["arp", "-batch"])).is_err());
        assert!(crate::show_op(&words(&["interfaces", "eth0\nx"])).is_err());
    }

    #[test]
    fn each_position_takes_only_its_own_shape() {
        assert!(ip_word("eth0.20").is_ok());
        assert!(ip_word("fe80::1/64").is_ok());
        assert!(ip_word("-batch").is_err());
        assert!(ip_word("a;b").is_err());
        assert!(iface_word("eth0").is_ok());
        assert!(iface_word("../x").is_err());
        assert!(mac_word("aa:bb:cc:dd:ee:ff").is_ok());
        assert!(mac_word("aa:bb:cc:dd:ee:ff any").is_err());
        assert!(mac_word("all").is_err());
        assert_eq!(mapping_words("tcp", "8080").unwrap(), ("tcp", 8080));
        assert!(mapping_words("tcp all", "1").is_err());
        assert!(mapping_words("udp", "0").is_err());
        assert!(mapping_words("udp", "70000").is_err());
    }
}
