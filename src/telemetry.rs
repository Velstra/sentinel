//! One bounded collector fans out to all authenticated SSE clients. A browser
//! never drains the kernel ring itself; slow clients retain only one snapshot.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    io::Read,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::watch;

pub struct Hub {
    sender: watch::Sender<Value>,
    started: AtomicBool,
}
impl Default for Hub {
    fn default() -> Self {
        let (sender, _) = watch::channel(json!({"collecting":true}));
        Self {
            sender,
            started: AtomicBool::new(false),
        }
    }
}
impl Hub {
    pub fn subscribe(self: &Arc<Self>) -> watch::Receiver<Value> {
        let receiver = self.sender.subscribe();
        if !self.started.swap(true, Ordering::AcqRel) {
            let weak = Arc::downgrade(self);
            tokio::spawn(run(weak));
        }
        receiver
    }
}
async fn run(hub: Weak<Hub>) {
    let mut collector = Collector::default();
    loop {
        if hub.strong_count() == 0 {
            break;
        }
        let result = tokio::task::spawn_blocking(move || {
            let value = collector.collect(true);
            (collector, value)
        })
        .await;
        let Ok((state, value)) = result else {
            if let Some(hub) = hub.upgrade() {
                hub.started.store(false, Ordering::Release);
            }
            break;
        };
        collector = state;
        let Some(hub) = hub.upgrade() else {
            break;
        };
        hub.sender.send_replace(value);
        drop(hub);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Fleet telemetry is a non-draining snapshot. The local API remains the sole
/// packet-ring consumer; cumulative interface counters let controllers derive rates.
pub fn fleet_snapshot() -> Value {
    Collector::default().collect(false)
}

#[derive(Default)]
struct Collector {
    previous: Option<(Instant, BTreeMap<String, [u64; 4]>)>,
    events: VecDeque<Value>,
    event_id: u64,
    sequence: u64,
}
impl Collector {
    fn collect(&mut self, include_events: bool) -> Value {
        let queries = [
            ("events", "packet-events 256"),
            ("conntrack", "firewall-state-summary 200"),
            ("nat_flows", "flows 100"),
            ("top_talkers", "top 20"),
            ("rule_counters", "rule-stats 512"),
            ("ha", "ha-status"),
        ];
        let mut data = BTreeMap::new();
        std::thread::scope(|scope| {
            let handles: Vec<_> = queries
                .iter()
                .filter(|(key, _)| include_events || *key != "events")
                .map(|(key, query)| (*key, scope.spawn(move || crate::velstra::query(query))))
                .collect();
            for (key, handle) in handles {
                data.insert(
                    key,
                    handle
                        .join()
                        .unwrap_or_else(|_| Err(anyhow::anyhow!("collector task failed"))),
                );
            }
        });
        let mut errors = serde_json::Map::new();
        let mut answer = |key: &str| -> Option<String> {
            match data
                .remove(key)
                .unwrap_or_else(|| Err(anyhow::anyhow!("missing collector result")))
            {
                Ok(text) if !text.trim_start().starts_with("error:") => Some(text),
                Ok(text) => {
                    errors.insert(key.into(), json!(text.trim()));
                    None
                }
                Err(error) => {
                    errors.insert(key.into(), json!(format!("{error:#}")));
                    None
                }
            }
        };
        let events = if include_events {
            answer("events")
        } else {
            None
        };
        if let Some(text) = events {
            self.append_events(&text);
        }
        let conntrack = answer("conntrack").and_then(|v| serde_json::from_str::<Value>(&v).ok());
        let nat = answer("nat_flows");
        let top = answer("top_talkers");
        let rules = answer("rule_counters").and_then(|v| serde_json::from_str::<Value>(&v).ok());
        let ha = answer("ha").and_then(|v| serde_json::from_str::<Value>(&v).ok());
        let mut routing = serde_json::Map::new();
        // The commands are fixed, bounded and contain no user input. A stalled
        // routing daemon cannot hold the collector or its children indefinitely.
        for (name, args) in [
            ("bgp", vec!["show", "bgp", "neighbors"]),
            ("ospf", vec!["show", "ospf", "neighbors"]),
            ("routes", vec!["show", "routes"]),
        ] {
            match command("wren", &args) {
                Ok(text) => {
                    routing.insert(name.into(), json!(text));
                }
                Err(e) => {
                    errors.insert(name.into(), json!(format!("{e:#}")));
                }
            }
        }
        let vpn = match command("wg", &["show", "all", "latest-handshakes"]) {
            Ok(v) => Some(v),
            Err(e) => {
                errors.insert("wireguard".into(), json!(format!("{e:#}")));
                None
            }
        };
        let interfaces = match std::fs::read_to_string("/proc/net/dev") {
            Ok(text) => self.interfaces(&text, Instant::now()),
            Err(e) => {
                errors.insert("interfaces".into(), json!(e.to_string()));
                Vec::new()
            }
        };
        let total = conntrack.as_ref().and_then(|value| value["total"].as_u64());
        let states = conntrack.and_then(|v| {
            v["states"]
                .as_array()
                .map(|a| a.iter().take(200).cloned().collect::<Vec<_>>())
        });
        self.sequence += 1;
        json!({"sequence":self.sequence,"sampled_at":crate::aaa::unix_now(),"interfaces":interfaces,
            "events":self.events,"oldest_event_id":self.events.front().and_then(|v|v["id"].as_u64()),"next_event_id":self.event_id+1,
            "conntrack":{"total":total,"states":states,"sample_limit":200,"nat_flows":nat},"top_talkers":top,"top_talkers_scope":"NAT flows; node-local counters",
            "rule_counters":rules,"ha":ha,"routing":routing,"wireguard":vpn,"errors":errors})
    }
    fn append_events(&mut self, text: &str) {
        for line in text.lines() {
            if let Ok(mut event) = serde_json::from_str::<Value>(line) {
                if !event.is_object() {
                    continue;
                }
                self.event_id += 1;
                event["id"] = json!(self.event_id);
                if let Some(index) = event["interface"].as_u64() {
                    let mut name = [0i8; libc::IF_NAMESIZE];
                    if !unsafe { libc::if_indextoname(index as u32, name.as_mut_ptr()) }.is_null() {
                        event["interface_name"] = json!(
                            unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_string_lossy()
                        );
                    }
                }
                self.events.push_back(event);
                while self.events.len() > 512 {
                    self.events.pop_front();
                }
            }
        }
    }
    fn interfaces(&mut self, text: &str, now: Instant) -> Vec<Value> {
        let counters = parse_interfaces(text);
        let rows=counters.iter().map(|(name,values)| {
            let rates=self.previous.as_ref().and_then(|(at,old)| old.get(name).and_then(|old| rates(*old,*values,now.duration_since(*at).as_secs_f64())));
            let carrier=std::fs::read_to_string(format!("/sys/class/net/{name}/operstate")).ok().map(|v|v.trim().to_string());
            json!({"name":name,"state":carrier,"rx_bytes":values[0],"tx_bytes":values[1],"rx_packets":values[2],"tx_packets":values[3],"rates":rates.map(|r|json!({"rx_bytes_per_second":r[0],"tx_bytes_per_second":r[1],"rx_pps":r[2],"tx_pps":r[3]}))})
        }).collect();
        self.previous = Some((now, counters));
        rows
    }
}
fn parse_interfaces(text: &str) -> BTreeMap<String, [u64; 4]> {
    text.lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let fields: Vec<_> = rest.split_whitespace().collect();
            if fields.len() < 10 {
                return None;
            }
            Some((
                name.trim().into(),
                [
                    fields[0].parse().ok()?,
                    fields[8].parse().ok()?,
                    fields[1].parse().ok()?,
                    fields[9].parse().ok()?,
                ],
            ))
        })
        .collect()
}
fn rates(old: [u64; 4], new: [u64; 4], elapsed: f64) -> Option<[f64; 4]> {
    if elapsed <= 0.0 || new.iter().zip(old).any(|(n, o)| *n < o) {
        return None;
    }
    Some(std::array::from_fn(|i| (new[i] - old[i]) as f64 / elapsed))
}

fn command(binary: &str, args: &[&str]) -> Result<String> {
    use std::os::unix::process::CommandExt;
    let mut child = std::process::Command::new(crate::system::bin(binary))
        .args(args)
        .process_group(0)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("starting {binary}"))?;
    let stdout = child.stdout.take().context("telemetry command stdout")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(1_048_577).read_to_end(&mut bytes);
        (result, bytes)
    });
    let deadline = Instant::now() + Duration::from_millis(750);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            result => {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                break match result {
                    Err(e) => Err(e.into()),
                    _ => Err(anyhow::anyhow!("{binary} telemetry timed out")),
                };
            }
        }
    };
    // A wrapper may have exited while a descendant still owns stdout. Close
    // the entire private process group before joining the bounded reader.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let (read, bytes) = reader
        .join()
        .map_err(|_| anyhow::anyhow!("telemetry reader failed"))?;
    ensure!(status?.success(), "{binary} telemetry unavailable");
    read?;
    ensure!(
        bytes.len() <= 1_048_576,
        "{binary} telemetry exceeds 1 MiB limit"
    );
    Ok(String::from_utf8(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stalled_commands_and_inherited_stdout_are_bounded_without_orphans() {
        let start = Instant::now();
        assert!(command("sh", &["-c", "exec sleep 10"]).is_err());
        assert!(start.elapsed() < Duration::from_secs(3));
        let start = Instant::now();
        assert_eq!(command("sh", &["-c", "sleep 10 & exit 0"]).unwrap(), "");
        assert!(start.elapsed() < Duration::from_secs(3));
    }
    #[test]
    fn rates_use_elapsed_time_and_resets_are_unknown_not_spikes() {
        assert_eq!(
            rates([100, 200, 10, 20], [300, 600, 30, 60], 2.0),
            Some([100.0, 200.0, 10.0, 20.0])
        );
        assert_eq!(rates([100; 4], [0; 4], 1.0), None);
        assert_eq!(rates([0; 4], [1; 4], 0.0), None);
        let parsed =
            parse_interfaces(" eth0: 100 10 0 0 0 0 0 0 200 20 0 0 0 0 0 0\nmalformed: x\n");
        assert_eq!(parsed["eth0"], [100, 200, 10, 20]);
        assert_eq!(parsed.len(), 1);
    }
    #[test]
    fn retained_event_window_is_bounded_and_ids_expose_slow_client_gaps() {
        let mut c = Collector::default();
        c.append_events("broken\nnull\n[]\n");
        for _ in 0..600 {
            c.append_events(r#"{"src":"2001:db8::1","dst":"2001:db8::2","rule":"web","action":"drop","interface":0}"#);
        }
        assert_eq!(c.events.len(), 512);
        assert_eq!(c.events.front().unwrap()["id"], 89);
        assert_eq!(c.events.back().unwrap()["id"], 600);
    }
    #[tokio::test]
    async fn slow_subscribers_hold_only_the_latest_snapshot() {
        let hub = Hub::default();
        let mut a = hub.sender.subscribe();
        let b = hub.sender.subscribe();
        for n in 0..1000 {
            hub.sender.send_replace(json!({"sequence":n}));
        }
        a.changed().await.unwrap();
        assert_eq!(a.borrow_and_update()["sequence"], 999);
        assert_eq!(b.borrow()["sequence"], 999);
    }
}
