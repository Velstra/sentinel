//! Strict boot-entry identities. A filename is not proof of a healthy image:
//! callers must also verify its actual ESP source, release, verity and bytes.
//! Community's fixed slot names and Enterprise's versioned UKIs never imply
//! one another's physical slot; that comes from the running verity device.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Image<'a> {
    Slot(&'static str),
    Release(&'a str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Entry<'a> {
    pub image: Image<'a>,
    pub counted: bool,
}

/// The immutable build chooses the update format, not a runtime environment
/// variable, URL, license or browser-supplied entry name. Existing Community
/// writers must not admit a native boot format they cannot preserve as fallback.
pub(crate) fn native_enabled() -> bool {
    option_env!("VELSTRA_ENTERPRISE_UPDATE_BIN").is_some()
}

pub(crate) fn native_version(version: &str) -> bool {
    // The native verity partition label is sentinel_<version>_verity: GPT has
    // 36 characters, leaving at most 20 for the complete version token.
    if version.len() > 20 {
        return false;
    }
    let Some(core) = version
        .strip_prefix('v')
        .and_then(|v| v.strip_suffix("-lts"))
    else {
        return false;
    };
    let mut count = 0;
    for part in core.split('.') {
        count += 1;
        if part.is_empty()
            || !part.bytes().all(|b| b.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return false;
        }
    }
    count == 3
}

impl<'a> Entry<'a> {
    pub(crate) fn parse(name: &'a str, native: bool) -> Option<Self> {
        if name.len() > 80 {
            return None;
        }
        let core = name.strip_suffix(".efi")?;
        let (image, counted) = match core.split_once('+') {
            None => (core, false),
            Some((image, tries)) => {
                let mut parts = tries.split('-');
                let counter = |part: &str| {
                    !part.is_empty()
                        && part.len() <= 10
                        && part.bytes().all(|b| b.is_ascii_digit())
                        && part.parse::<u32>().is_ok()
                };
                if !counter(parts.next()?)
                    || parts.next().is_some_and(|part| !counter(part))
                    || parts.next().is_some()
                {
                    return None;
                }
                (image, true)
            }
        };
        let image = match image {
            "sentinel-a" => Image::Slot("sentinel-a"),
            "sentinel-b" => Image::Slot("sentinel-b"),
            other if native => {
                let version = other.strip_prefix("sentinel_")?;
                if !native_version(version) {
                    return None;
                }
                Image::Release(version)
            }
            _ => return None,
        };
        Some(Self { image, counted })
    }

    pub(crate) fn matches_running(self, slot: &str, version: &str) -> bool {
        matches!(slot, "sentinel-a" | "sentinel-b")
            && match self.image {
                Image::Slot(expected) => slot == expected,
                Image::Release(expected) => version == expected,
            }
    }

    pub(crate) fn permanent_for(self, slot: &str, version: &str) -> bool {
        !self.counted && self.matches_running(slot, version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_and_native_names_have_distinct_physical_identity_rules() {
        for slot in ["sentinel-a", "sentinel-b"] {
            for native in [false, true] {
                let name = format!("{slot}.efi");
                let entry = Entry::parse(&name, native).unwrap();
                assert_eq!(
                    entry.image,
                    Image::Slot(if slot == "sentinel-a" {
                        "sentinel-a"
                    } else {
                        "sentinel-b"
                    })
                );
                assert!(entry.permanent_for(slot, "2.0.1"));
                assert!(!entry.matches_running(
                    if slot == "sentinel-a" {
                        "sentinel-b"
                    } else {
                        "sentinel-a"
                    },
                    "2.0.1"
                ));
            }
        }
        let name = "sentinel_v1.2.3-lts.efi";
        assert!(Entry::parse(name, false).is_none());
        let entry = Entry::parse(name, true).unwrap();
        assert_eq!(entry.image, Image::Release("v1.2.3-lts"));
        for slot in ["sentinel-a", "sentinel-b"] {
            assert!(entry.permanent_for(slot, "v1.2.3-lts"));
            assert!(!entry.matches_running(slot, "v1.2.4-lts"));
        }
        assert!(!entry.matches_running("unknown", "v1.2.3-lts"));
    }

    #[test]
    fn any_count_suffix_is_unassessed_even_zero_tries_or_zero_done() {
        for base in ["sentinel-a", "sentinel-b", "sentinel_v1.2.3-lts"] {
            for suffix in ["+3", "+3-0", "+2-1", "+0-3", "+0", "+4294967295-4294967295"] {
                let name = format!("{base}{suffix}.efi");
                let entry = Entry::parse(&name, true).unwrap();
                assert!(entry.counted);
                assert!(!entry.permanent_for("sentinel-a", "v1.2.3-lts"));
            }
        }
    }

    #[test]
    fn malformed_names_paths_counts_and_oversized_versions_are_refused() {
        for name in [
            "sentinel-a",
            "sentinel-a.efi/other",
            "../sentinel-a.efi",
            "SENTINEL-A.efi",
            "sentinel-a*.efi",
            "sentinel-a+.efi",
            "sentinel-a+3-.efi",
            "sentinel-a+-1.efi",
            "sentinel-a+3-0-0.efi",
            "sentinel-a+4294967296.efi",
            "sentinel-a+3+0.efi",
            "sentinel-a+３.efi",
            "sentinel-a\n.efi",
            "sentinel-a\0.efi",
            "sentinel_v1.2.3-lts/other.efi",
            "sentinel_v1.2.3-lts+3-0.efi\n",
            "sentinel_v01.2.3-lts.efi",
            "sentinel_v1.2.3.efi",
            "sentinel_v1.2-lts.efi",
            "sentinel_v1.2.3.4-lts.efi",
            "sentinel_v12345678901234.0.0-lts.efi",
        ] {
            assert!(Entry::parse(name, true).is_none(), "{name:?}");
        }
        assert!(native_version("v0.0.0-lts"));
        assert!(native_version("v12345678901.0.0-lts")); // Exactly 20 bytes.
        assert!(!native_version("v123456789012.0.0-lts"));
    }
}
