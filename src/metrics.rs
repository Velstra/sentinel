//! What the box looked like before now (roadmap: history).
//!
//! Live counters answer "what is happening"; they cannot answer "was this
//! happening at three in the morning last Tuesday", which is the question an
//! operator actually arrives with. The flow exporter answers it too, but only
//! for somebody who already runs a collector — and a firewall that needs a
//! second machine before it can draw its own throughput graph is not finished.
//!
//! So: a ring per series on disk, sampled on a timer, bounded by construction.
//!
//! **Ring, not append-and-compact.** A file that grows until something trims it
//! is a file that fills a partition on the one weekend nobody is looking, and
//! compaction rewrites the whole history to drop its oldest hour. A ring writes
//! sixteen bytes and moves an index; the size on disk is decided when the file
//! is created and never changes.
//!
//! **Counters are stored raw, and rates derived on read.** A counter that was
//! reset — an interface that went away and came back, a reboot — shows up as a
//! sample lower than the one before it. Storing rates would bake a meaningless
//! spike into the history permanently; deriving them means the reset is simply
//! a gap, which is what it was.

use anyhow::{Context, Result, bail};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Where the rings live. Under the appliance's own state, not `/run`: history
/// that does not survive a reboot is not history.
const DEFAULT_METRICS_DIR: &str = "/var/lib/sentinel/metrics";

/// Where the rings live for this process.
///
/// Overridable by `SENTINEL_METRICS_DIR`, like the appliance's other paths, so
/// the browser tests can drive a real history without a writable `/var/lib` —
/// and so an operator can point a box with a read-only root somewhere else.
pub fn dir() -> PathBuf {
    std::env::var_os("SENTINEL_METRICS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_METRICS_DIR))
}

const MAGIC: &[u8; 4] = b"VSH1";
const HEADER_LEN: u64 = 16;
const RECORD_LEN: u64 = 16;

/// One stored observation: when, and what the counter read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// Unix seconds.
    pub at: u64,
    /// The raw counter, or the raw value for a gauge.
    pub value: u64,
}

/// A resolution: how often it is written, and how many it keeps.
///
/// Three of them, for the three questions people actually ask: what happened in
/// the last hour, what happened yesterday, and is this month worse than last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolution {
    /// Directory name and the word an operator types.
    pub name: &'static str,
    /// Seconds between samples.
    pub step: u64,
    /// How many samples are kept.
    pub keep: u32,
}

pub const RESOLUTIONS: [Resolution; 3] = [
    // A day at one-minute resolution.
    Resolution {
        name: "minute",
        step: 60,
        keep: 1440,
    },
    // A month at fifteen minutes.
    Resolution {
        name: "quarter",
        step: 900,
        keep: 2976,
    },
    // Two years at a day. Cheap, and the only one that answers "is this normal
    // for February".
    Resolution {
        name: "day",
        step: 86_400,
        keep: 730,
    },
];

/// A series name reduced to something that is safe as a file name.
///
/// Series names carry interface names, which an operator chooses. Without this
/// a series called `../../etc/passwd` would be a path, and the fact that only
/// the appliance itself names series today is not a reason to leave that open.
fn safe(series: &str) -> String {
    series
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn path_for(root: &Path, series: &str, res: &Resolution) -> PathBuf {
    root.join(res.name).join(format!("{}.ring", safe(series)))
}

/// Open (creating and sizing if new) the ring for one series at one resolution.
fn open_ring(root: &Path, series: &str, res: &Resolution) -> Result<std::fs::File> {
    let path = path_for(root, series, res);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let exists = path.exists();
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    if !exists || f.metadata()?.len() < HEADER_LEN {
        // Header, then the whole ring as zeroes. Allocating it once is what
        // makes the size on disk a decision rather than a surprise.
        let mut header = Vec::with_capacity(HEADER_LEN as usize);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&(res.step as u32).to_le_bytes());
        header.extend_from_slice(&res.keep.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes()); // next write index
        f.set_len(0)?;
        f.write_all(&header)?;
        f.write_all(&vec![0u8; (res.keep as u64 * RECORD_LEN) as usize])?;
        f.seek(SeekFrom::Start(0))?;
    }
    Ok(f)
}

fn read_header(f: &mut std::fs::File) -> Result<(u32, u32)> {
    let mut buf = [0u8; HEADER_LEN as usize];
    f.seek(SeekFrom::Start(0))?;
    f.read_exact(&mut buf).context("reading the ring header")?;
    if &buf[0..4] != MAGIC {
        bail!("not a sentinel metrics ring (bad magic)");
    }
    let keep = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let next = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    Ok((keep, next))
}

/// Record one observation, unless the newest one is younger than the step.
///
/// The step check is what lets every resolution be fed from the same sampler
/// run: the minute ring takes every call, the daily ring takes one in 1440, and
/// nothing has to schedule them separately.
pub fn record(root: &Path, series: &str, at: u64, value: u64) -> Result<()> {
    for res in &RESOLUTIONS {
        let mut f = open_ring(root, series, res)?;
        let (keep, next) = read_header(&mut f)?;
        if keep == 0 {
            continue;
        }
        // The newest record is the one before `next`.
        let newest_idx = (next + keep - 1) % keep;
        let mut rec = [0u8; RECORD_LEN as usize];
        f.seek(SeekFrom::Start(HEADER_LEN + newest_idx as u64 * RECORD_LEN))?;
        f.read_exact(&mut rec)?;
        let newest_at = u64::from_le_bytes(rec[0..8].try_into().unwrap());
        if newest_at != 0 && at < newest_at.saturating_add(res.step) {
            continue; // not due at this resolution yet
        }
        let mut out = [0u8; RECORD_LEN as usize];
        out[0..8].copy_from_slice(&at.to_le_bytes());
        out[8..16].copy_from_slice(&value.to_le_bytes());
        f.seek(SeekFrom::Start(HEADER_LEN + next as u64 * RECORD_LEN))?;
        f.write_all(&out)?;
        let advanced = (next + 1) % keep;
        f.seek(SeekFrom::Start(12))?;
        f.write_all(&advanced.to_le_bytes())?;
    }
    Ok(())
}

/// Every stored sample for one series at one resolution, oldest first.
pub fn read(root: &Path, series: &str, res: &Resolution) -> Result<Vec<Sample>> {
    let path = path_for(root, series, res);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut f =
        std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
    let mut buf = [0u8; HEADER_LEN as usize];
    f.read_exact(&mut buf)?;
    if &buf[0..4] != MAGIC {
        bail!("not a sentinel metrics ring (bad magic)");
    }
    let mut rest = Vec::new();
    f.read_to_end(&mut rest)?;
    let mut out: Vec<Sample> = rest
        .chunks_exact(RECORD_LEN as usize)
        .map(|c| Sample {
            at: u64::from_le_bytes(c[0..8].try_into().unwrap()),
            value: u64::from_le_bytes(c[8..16].try_into().unwrap()),
        })
        .filter(|s| s.at != 0)
        .collect();
    // The ring is written out of order by construction; time is the order that
    // means anything.
    out.sort_by_key(|s| s.at);
    Ok(out)
}

/// Turn stored counters into per-second rates.
///
/// A pair whose value went *down* is a counter that was reset — an interface
/// that went away and came back, or a reboot — and the honest answer is a gap,
/// not a negative rate and not a spike. A pair further apart than `max_gap`
/// seconds is also a gap: averaging across a hole the box was off for would
/// draw a flat line through time that has no data.
pub fn rates(samples: &[Sample], max_gap: u64) -> Vec<(u64, Option<f64>)> {
    let mut out = Vec::with_capacity(samples.len());
    for pair in samples.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        let dt = b.at.saturating_sub(a.at);
        let rate = if dt == 0 || dt > max_gap || b.value < a.value {
            None
        } else {
            Some((b.value - a.value) as f64 / dt as f64)
        };
        out.push((b.at, rate));
    }
    out
}

/// The resolution named `name`, if there is one.
pub fn resolution(name: &str) -> Option<&'static Resolution> {
    RESOLUTIONS.iter().find(|r| r.name == name)
}

// ---- sampling -------------------------------------------------------------

/// Per-interface byte and packet counters, straight from the kernel.
///
/// `/proc/net/dev` rather than `ip -s link`: no process to spawn, and the
/// format has not changed in twenty years. An interface that has just gone away
/// is simply absent, which the ring records as a gap.
pub fn interface_counters() -> Result<Vec<(String, u64, u64)>> {
    let text = std::fs::read_to_string("/proc/net/dev").context("reading /proc/net/dev")?;
    let mut out = Vec::new();
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name == "lo" {
            continue;
        }
        let f: Vec<&str> = rest.split_whitespace().collect();
        // receive bytes is field 0, transmit bytes is field 8.
        if f.len() < 9 {
            continue;
        }
        let (Ok(rx), Ok(tx)) = (f[0].parse::<u64>(), f[8].parse::<u64>()) else {
            continue;
        };
        out.push((name.to_string(), rx, tx));
    }
    Ok(out)
}

/// Take one round of samples and write them into every resolution.
///
/// Best-effort per series: a counter that cannot be read must not stop the
/// others being recorded, because the one that fails is usually the one whose
/// interface just disappeared — which is exactly when the neighbouring graphs
/// matter.
pub fn sample_once(root: &Path, at: u64) -> Result<usize> {
    let mut written = 0;
    for (name, rx, tx) in interface_counters().unwrap_or_default() {
        for (suffix, value) in [("rx", rx), ("tx", tx)] {
            if let Err(e) = record(root, &format!("iface.{name}.{suffix}"), at, value) {
                eprintln!("warning: recording iface.{name}.{suffix}: {e}");
            } else {
                written += 1;
            }
        }
    }
    // Sessions: a gauge, not a counter, so the reader must not derive a rate
    // from it. The name says so.
    if let Some(n) = session_count() {
        if let Err(e) = record(root, "gauge.sessions", at, n) {
            eprintln!("warning: recording gauge.sessions: {e}");
        } else {
            written += 1;
        }
    }
    Ok(written)
}

/// How many flows the data plane is tracking, if it will say.
fn session_count() -> Option<u64> {
    let reply = crate::velstra::query("stats").ok()?;
    // The agent prints `key: value` lines; the flow count is the one that
    // matters here and anything else it says is ignored on purpose — this is a
    // graph, not a parser for the whole reply.
    for line in reply.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("flow") || lower.contains("conntrack") {
            if let Some(n) = line
                .split(|c: char| !c.is_ascii_digit())
                .rfind(|s| !s.is_empty())
                .and_then(|s| s.parse::<u64>().ok())
            {
                return Some(n);
            }
        }
    }
    None
}

/// Every series that has been recorded, at any resolution.
pub fn series(root: &Path) -> Vec<String> {
    let mut names = std::collections::BTreeSet::new();
    for res in &RESOLUTIONS {
        let Ok(entries) = std::fs::read_dir(root.join(res.name)) else {
            continue;
        };
        for e in entries.flatten() {
            if let Some(stem) = e.path().file_stem().and_then(|s| s.to_str()) {
                names.insert(stem.to_string());
            }
        }
    }
    names.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sentinel-metrics-{}-{tag}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The size on disk is decided when the ring is made, and stays there. That
    /// is the whole reason for a ring: a file that grows until something trims
    /// it fills a partition on the weekend nobody is looking.
    #[test]
    fn a_ring_is_a_fixed_size_and_wraps() {
        let root = scratch("wrap");
        let res = Resolution {
            name: "minute",
            step: 60,
            keep: 5,
        };
        let path = path_for(&root, "iface.eth0.rx", &res);
        // Ten samples into a ring of five, an hour apart so each is due.
        for i in 0..10u64 {
            let mut f = open_ring(&root, "iface.eth0.rx", &res).unwrap();
            let (keep, next) = read_header(&mut f).unwrap();
            assert_eq!(keep, 5);
            let mut out = [0u8; RECORD_LEN as usize];
            out[0..8].copy_from_slice(&(1_000 + i * 3600).to_le_bytes());
            out[8..16].copy_from_slice(&(i * 100).to_le_bytes());
            f.seek(SeekFrom::Start(HEADER_LEN + next as u64 * RECORD_LEN))
                .unwrap();
            f.write_all(&out).unwrap();
            let advanced = (next + 1) % keep;
            f.seek(SeekFrom::Start(12)).unwrap();
            f.write_all(&advanced.to_le_bytes()).unwrap();
        }
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            HEADER_LEN + 5 * RECORD_LEN,
            "the ring grew"
        );
        let got = read(&root, "iface.eth0.rx", &res).unwrap();
        assert_eq!(got.len(), 5, "a ring of five kept {}", got.len());
        // …and what it kept is the newest five, in time order.
        assert_eq!(got.first().unwrap().value, 500);
        assert_eq!(got.last().unwrap().value, 900);
    }

    /// Every resolution is fed from the same sampler run: the minute ring takes
    /// each call and the coarser ones take only what is due, so nothing has to
    /// schedule them separately.
    #[test]
    fn a_coarser_resolution_takes_only_what_is_due() {
        let root = scratch("due");
        // Ten minutes of samples, one a minute.
        for i in 0..10u64 {
            record(&root, "iface.eth0.rx", 100_000 + i * 60, i * 1_000).unwrap();
        }
        let minute = read(&root, "iface.eth0.rx", resolution("minute").unwrap()).unwrap();
        assert_eq!(minute.len(), 10, "the minute ring took every sample");
        let quarter = read(&root, "iface.eth0.rx", resolution("quarter").unwrap()).unwrap();
        assert_eq!(
            quarter.len(),
            1,
            "ten minutes is one sample at fifteen-minute resolution, got {}",
            quarter.len()
        );
    }

    /// A counter that went down was reset, and the honest answer is a gap — not
    /// a negative rate, and emphatically not the enormous spike that treating
    /// the wrap as a delta would draw.
    #[test]
    fn a_counter_reset_is_a_gap_rather_than_a_spike() {
        let samples = vec![
            Sample {
                at: 0,
                value: 1_000,
            },
            Sample {
                at: 10,
                value: 2_000,
            },
            // The interface went away and came back: the counter restarted.
            Sample { at: 20, value: 50 },
            Sample { at: 30, value: 550 },
        ];
        let r = rates(&samples, 120);
        assert_eq!(r[0], (10, Some(100.0)), "an ordinary delta");
        assert_eq!(r[1], (20, None), "the reset must be a gap");
        assert_eq!(r[2], (30, Some(50.0)), "and the next pair recovers");
    }

    /// A hole the box was switched off for is a hole. Averaging across it would
    /// draw a confident flat line through time that has no data in it.
    #[test]
    fn a_long_gap_is_not_averaged_across() {
        let samples = vec![
            Sample { at: 0, value: 0 },
            // Two hours later — the box was off.
            Sample {
                at: 7_200,
                value: 7_200_000,
            },
        ];
        assert_eq!(rates(&samples, 300)[0], (7_200, None));
    }

    /// A series name carries an interface name, which somebody chooses. Without
    /// reducing it, a name with a slash in it would be a path.
    #[test]
    fn a_series_name_cannot_escape_its_directory() {
        assert_eq!(safe("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(safe("iface.eth0.rx"), "iface.eth0.rx");
        assert_eq!(safe("iface.br-lan.tx"), "iface.br-lan.tx");
    }
}
