//! One bounded collector fans out to all authenticated SSE clients. A browser
//! never drains the kernel ring itself; slow clients retain only one snapshot.
//! The collector runs only while somebody is watching: each sample costs a
//! dozen agent queries and child processes, which an appliance nobody has open
//! in a browser should not be paying every second.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    io::Read,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};

type Sampler = dyn Fn(&mut Collector) -> Value + Send + Sync;

pub struct Hub {
    sender: watch::Sender<Value>,
    /// Whether a collector task is running. A mutex, not a flag: subscribing
    /// and the collector's "nobody left, stop" decision must not interleave, or
    /// a client arriving at that moment would wait on a collector that just
    /// quit.
    running: Mutex<bool>,
    sample: Arc<Sampler>,
    interval: Duration,
}
impl Default for Hub {
    fn default() -> Self {
        Self::with_sampler(Duration::from_secs(1), |c| c.collect(true))
    }
}
impl Hub {
    fn with_sampler(
        interval: Duration,
        sample: impl Fn(&mut Collector) -> Value + Send + Sync + 'static,
    ) -> Self {
        let (sender, _) = watch::channel(json!({"collecting":true}));
        Self {
            sender,
            running: Mutex::new(false),
            sample: Arc::new(sample),
            interval,
        }
    }
    /// A receiver of telemetry frames, starting the collector if this is the
    /// first one. Dropping the last receiver stops it again.
    pub fn subscribe(self: &Arc<Self>) -> watch::Receiver<Value> {
        let mut running = self.running.lock().unwrap_or_else(|p| p.into_inner());
        let receiver = self.sender.subscribe();
        if !*running {
            *running = true;
            tokio::spawn(run(Arc::downgrade(self)));
        }
        receiver
    }
    /// Stop when nobody is subscribed. Checked under the same lock a subscriber
    /// takes, so a subscriber either is counted here or starts a new collector.
    fn stop_if_unwatched(&self) -> bool {
        let mut running = self.running.lock().unwrap_or_else(|p| p.into_inner());
        if self.sender.receiver_count() > 0 {
            return false;
        }
        *running = false;
        // The next viewer must not be shown a frame from whenever the last one
        // left; it waits for a fresh sample like the very first viewer did.
        self.sender.send_replace(json!({"collecting":true}));
        true
    }
}
async fn run(hub: Weak<Hub>) {
    let mut collector = Collector::default();
    loop {
        let Some((sample, interval)) = hub.upgrade().map(|h| (h.sample.clone(), h.interval)) else {
            break;
        };
        let result = tokio::task::spawn_blocking(move || {
            let value = sample(&mut collector);
            (collector, value)
        })
        .await;
        let Some(hub) = hub.upgrade() else {
            break;
        };
        let Ok((state, value)) = result else {
            *hub.running.lock().unwrap_or_else(|p| p.into_inner()) = false;
            break;
        };
        collector = state;
        hub.sender.send_replace(value);
        if hub.stop_if_unwatched() {
            break;
        }
        drop(hub);
        tokio::time::sleep(interval).await;
    }
}

/// How often a live stream re-checks the credential that opened it. Checking
/// on every frame meant a token-file read and parse per client per second;
/// every few seconds still ends a revoked session promptly.
const REVALIDATE: Duration = Duration::from_secs(5);

/// One client's stream of frames. The credential is re-checked through
/// `still_authorized` at most every `REVALIDATE`, and the stream ends with an
/// error the first time it fails. Each client also gets the route table only
/// when it changed since the last frame it was sent.
pub fn client_stream<F, Fut>(
    receiver: watch::Receiver<Value>,
    still_authorized: F,
) -> tokio_stream::wrappers::ReceiverStream<std::io::Result<Value>>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = bool> + Send,
{
    client_stream_every(receiver, REVALIDATE, still_authorized)
}

fn client_stream_every<F, Fut>(
    mut receiver: watch::Receiver<Value>,
    every: Duration,
    mut still_authorized: F,
) -> tokio_stream::wrappers::ReceiverStream<std::io::Result<Value>>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = bool> + Send,
{
    // Capacity one: a slow client holds at most one frame here besides the
    // latest in the watch channel, never a backlog.
    let (frames, stream) = mpsc::channel(1);
    tokio::spawn(async move {
        // The middleware authenticated this request a moment ago.
        let mut checked = tokio::time::Instant::now();
        let mut routes = None;
        loop {
            let value = receiver.borrow_and_update().clone();
            if checked.elapsed() >= every {
                if !still_authorized().await {
                    let _ = frames
                        .send(Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "telemetry credential revoked",
                        )))
                        .await;
                    return;
                }
                checked = tokio::time::Instant::now();
            }
            if frames
                .send(Ok(elide_unchanged_routes(value, &mut routes)))
                .await
                .is_err()
            {
                return;
            }
            // A client that went away releases its receiver at once, so the
            // collector can see that nobody is watching any more.
            tokio::select! {
                changed = receiver.changed() => if changed.is_err() { return },
                () = frames.closed() => return,
            }
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(stream)
}

/// The route table is the largest text in a frame and rarely changes. Send it
/// to a client once per change; otherwise mark it unchanged so the console
/// keeps the copy it has. Per client, because each joined at a different time.
fn elide_unchanged_routes(mut value: Value, last: &mut Option<u64>) -> Value {
    use std::hash::{Hash, Hasher};
    let Some(text) = value["routing"]["routes"].as_str() else {
        *last = None;
        return value;
    };
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut hasher);
    let hash = hasher.finish();
    if *last == Some(hash) {
        if let Some(routing) = value["routing"].as_object_mut() {
            routing.remove("routes");
            routing.insert("routes_unchanged".into(), json!(true));
        }
    } else {
        *last = Some(hash);
    }
    value
}

/// Fleet telemetry is a snapshot without packet events; cumulative interface
/// counters let controllers derive rates.
///
/// Counters only unless `[fleet] flow-telemetry` says otherwise: the console
/// on the box itself may show who talks to whom, but a controller elsewhere
/// receives that only where this box's operator opted in.
pub fn fleet_snapshot(flow_detail: bool) -> Value {
    let snapshot = Collector::default().collect(false);
    if flow_detail {
        snapshot
    } else {
        without_flow_detail(snapshot)
    }
}

/// The snapshot minus everything that names an endpoint: the conntrack state
/// sample, the NAT flow table and the top talkers (and any collector error
/// text about them). The totals and every counter stay.
fn without_flow_detail(mut snapshot: Value) -> Value {
    if let Some(conntrack) = snapshot["conntrack"].as_object_mut() {
        conntrack.remove("states");
        conntrack.remove("sample_limit");
        conntrack.remove("nat_flows");
    }
    if let Some(errors) = snapshot["errors"].as_object_mut() {
        errors.remove("nat_flows");
        errors.remove("top_talkers");
    }
    if let Some(root) = snapshot.as_object_mut() {
        root.remove("top_talkers");
        root.remove("top_talkers_scope");
        root.insert("flow_detail".into(), json!(false));
    }
    snapshot
}

#[derive(Default)]
struct Collector {
    previous: Option<(Instant, BTreeMap<String, [u64; 4]>)>,
    events: VecDeque<Value>,
    /// This reader's place in the agent's event log. The agent hands out the
    /// ids and keeps the events; reading them takes nothing from any other
    /// reader (`show firewall events`, a second console).
    cursor: u64,
    /// The agent run the cursor belongs to; ids restart with every run.
    epoch: Option<u64>,
    /// Events this view will never show: evicted from the agent's window before
    /// it read them, or dropped by a full kernel ring.
    lost: u64,
    /// The kernel's cumulative ring overflow count when this view started,
    /// so only overflows during it are counted as its loss.
    ring_lost_base: Option<u64>,
    sequence: u64,
    /// The running configuration's text and the links it holds for the data
    /// plane, re-derived only when the text changes: a held link that is down
    /// is shown as waiting for the datapath, not as merely "down".
    held: Option<(String, std::collections::BTreeSet<String>)>,
}
impl Collector {
    fn collect(&mut self, include_events: bool) -> Value {
        let events_query = events_query(self.cursor, self.epoch);
        let queries = [
            ("events", events_query.as_str()),
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
        let events_error =
            events.and_then(|text| match serde_json::from_str::<Value>(text.trim()) {
                Ok(page) => {
                    self.append_page(&page);
                    None
                }
                Err(error) => Some(format!("packet events: {error}")),
            });
        let conntrack = answer("conntrack").and_then(|v| serde_json::from_str::<Value>(&v).ok());
        let nat = answer("nat_flows");
        let top = answer("top_talkers");
        let rules = answer("rule_counters").and_then(|v| serde_json::from_str::<Value>(&v).ok());
        let ha = answer("ha").and_then(|v| serde_json::from_str::<Value>(&v).ok());
        if let Some(error) = events_error {
            errors.insert("events".into(), json!(error));
        }
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
        let held = self.held_links();
        let interfaces = match std::fs::read_to_string("/proc/net/dev") {
            Ok(text) => self.interfaces(&text, Instant::now(), |name| {
                held.contains(name) && crate::held_links::link_down(name)
            }),
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
            "events":self.events,"oldest_event_id":self.events.front().and_then(|v|v["id"].as_u64()),"next_event_id":self.cursor+1,
            "events_lost":self.lost,
            "conntrack":{"total":total,"states":states,"sample_limit":200,"nat_flows":nat},"top_talkers":top,"top_talkers_scope":"NAT flows; node-local counters",
            "rule_counters":rules,"ha":ha,"routing":routing,"wireguard":vpn,"errors":errors})
    }
    /// Take one `packet-events-since` page: advance the cursor and count what
    /// this view lost. A new agent run restarts the cursor rather than waiting
    /// for the new ids to reach the old one.
    fn append_page(&mut self, page: &Value) {
        let epoch = page["epoch"].as_u64();
        let first = self.epoch.is_none() || page["restarted"] == true;
        if self.epoch.is_some() && epoch != self.epoch && page["restarted"] == true {
            // The agent recognised the old run's cursor (it was sent its epoch)
            // and served this page from the start of the new run: take it.
            self.ring_lost_base = None;
            self.events.clear();
        } else if self.epoch.is_some() && epoch != self.epoch {
            // Ask again from the start of the new run on the next sample;
            // nothing in this page belongs to the old cursor.
            self.epoch = epoch;
            self.cursor = 0;
            self.ring_lost_base = None;
            // Their ids belong to the old run and would collide with the new.
            self.events.clear();
            return;
        }
        self.epoch = epoch;
        // What the agent evicted before this view first asked was never this
        // view's to lose; afterwards, every eviction it is told of is.
        if !first {
            self.lost += page["missed"].as_u64().unwrap_or(0);
        }
        if let Some(ring) = page["ring_lost"].as_u64() {
            let base = *self.ring_lost_base.get_or_insert(ring);
            self.lost += ring.saturating_sub(base);
            self.ring_lost_base = Some(ring);
        }
        self.cursor = page["cursor"].as_u64().unwrap_or(self.cursor);
        for event in page["events"].as_array().into_iter().flatten() {
            if !event.is_object() || event["id"].as_u64().is_none() {
                continue;
            }
            let mut event = event.clone();
            if let Some(index) = event["interface"].as_u64() {
                let mut name = [0i8; libc::IF_NAMESIZE];
                if !unsafe { libc::if_indextoname(index as u32, name.as_mut_ptr()) }.is_null() {
                    event["interface_name"] =
                        json!(unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_string_lossy());
                }
            }
            self.events.push_back(event);
            while self.events.len() > 512 {
                self.events.pop_front();
            }
        }
    }
    /// The links the running configuration holds for the data plane (see
    /// [`crate::held_links`]), parsed again only when the configuration moved.
    fn held_links(&mut self) -> std::collections::BTreeSet<String> {
        let text = crate::session::Session::running_snapshot()
            .or_else(|| std::fs::read_to_string(crate::session::DEFAULT_CONFIG).ok());
        let Some(text) = text else {
            return Default::default();
        };
        if let Some((_, held)) = self.held.as_ref().filter(|(seen, _)| *seen == text) {
            return held.clone();
        }
        let held = crate::config::Appliance::from_toml(&text)
            .map(|a| crate::held_links::held(&a))
            .unwrap_or_default();
        self.held = Some((text, held.clone()));
        held
    }
    /// One row per link. `held` says whether the link is a held link that is
    /// down right now; such a link is reported as waiting for the datapath,
    /// because "down" alone sends the operator to the cabling.
    fn interfaces(&mut self, text: &str, now: Instant, held: impl Fn(&str) -> bool) -> Vec<Value> {
        let counters = parse_interfaces(text);
        let rows=counters.iter().map(|(name,values)| {
            let rates=self.previous.as_ref().and_then(|(at,old)| old.get(name).and_then(|old| rates(*old,*values,now.duration_since(*at).as_secs_f64())));
            let held=held(name);
            let carrier=if held {Some(crate::held_links::HELD_STATE.to_string())} else {std::fs::read_to_string(format!("/sys/class/net/{name}/operstate")).ok().map(|v|v.trim().to_string())};
            json!({"name":name,"state":carrier,"held":held,"rx_bytes":values[0],"tx_bytes":values[1],"rx_packets":values[2],"tx_packets":values[3],"rates":rates.map(|r|json!({"rx_bytes_per_second":r[0],"tx_bytes_per_second":r[1],"rx_pps":r[2],"tx_pps":r[3]}))})
        }).collect();
        self.previous = Some((now, counters));
        rows
    }
}
/// The `packet-events-since` request for a cursor. The run the cursor belongs
/// to goes along, so the agent can tell an old run's cursor from one of its own
/// even when it is behind the new run's ids; an agent that predates the
/// argument ignores it.
fn events_query(cursor: u64, epoch: Option<u64>) -> String {
    match epoch {
        Some(epoch) => format!("packet-events-since {cursor} 512 {epoch}"),
        None => format!("packet-events-since {cursor} 512"),
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
    fn page(epoch: u64, ids: std::ops::RangeInclusive<u64>, missed: u64, ring: u64) -> Value {
        let events: Vec<Value> = ids
            .clone()
            .map(|id| json!({"id":id,"src":"2001:db8::1","action":"drop","interface":0}))
            .chain([json!(null), json!({"no":"id"})])
            .collect();
        json!({"epoch":epoch,"events":events,"cursor":ids.end(),"missed":missed,
            "ring_lost":ring,"restarted":false})
    }
    #[test]
    fn retained_event_window_is_bounded_and_follows_the_agents_ids() {
        let mut c = Collector::default();
        c.append_page(&page(1, 1..=300, 0, 0));
        c.append_page(&page(1, 301..=600, 0, 0));
        assert_eq!(c.events.len(), 512);
        assert_eq!(c.events.front().unwrap()["id"], 89);
        assert_eq!(c.events.back().unwrap()["id"], 600);
        assert_eq!(c.cursor, 600);
    }
    #[test]
    fn lost_events_count_only_what_this_view_missed() {
        let mut c = Collector::default();
        // Evicted and overflowed before this view started: not its loss.
        c.append_page(&page(1, 40..=50, 39, 1000));
        assert_eq!(c.lost, 0);
        c.append_page(&page(1, 60..=61, 9, 1003));
        assert_eq!(c.lost, 9 + 3);
        // A new agent run: start over from its first event, not from 61.
        c.append_page(&page(2, 1..=2, 0, 0));
        assert_eq!((c.cursor, c.events.len()), (0, 0));
        c.append_page(&page(2, 1..=2, 0, 0));
        assert_eq!(c.cursor, 2);
        assert_eq!(c.lost, 12);
    }
    /// The agent now recognises an old run's cursor by its epoch and serves the
    /// new run from its start, flagged `restarted`. That page is the right one
    /// and is taken at once, not thrown away for another round trip.
    #[test]
    fn a_restarted_page_from_a_new_run_is_taken_at_once() {
        let mut c = Collector::default();
        c.append_page(&page(1, 1..=5, 0, 7));
        assert_eq!(
            events_query(c.cursor, c.epoch),
            "packet-events-since 5 512 1"
        );
        let mut restarted = page(2, 1..=3, 0, 0);
        restarted["restarted"] = json!(true);
        c.append_page(&restarted);
        assert_eq!((c.epoch, c.cursor), (Some(2), 3));
        let ids: Vec<_> = c.events.iter().map(|e| e["id"].as_u64().unwrap()).collect();
        assert_eq!(ids, [1, 2, 3], "only the new run's events, none of the old");
        assert_eq!(c.lost, 0);
        assert_eq!(events_query(0, None), "packet-events-since 0 512");
    }
    /// A zoned link held down for the data plane reads as waiting for it, not
    /// as a plain "down" that sends the operator to the cabling.
    #[test]
    fn a_held_dark_link_is_reported_as_waiting_for_the_datapath() {
        let mut c = Collector::default();
        let text =
            " lan0: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n wan0: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n";
        let rows = c.interfaces(text, Instant::now(), |name| name == "lan0");
        let lan = rows.iter().find(|r| r["name"] == "lan0").unwrap();
        assert_eq!(lan["state"], crate::held_links::HELD_STATE);
        assert_eq!(lan["held"], true);
        let wan = rows.iter().find(|r| r["name"] == "wan0").unwrap();
        assert_eq!(wan["held"], false);
        assert_ne!(wan["state"], crate::held_links::HELD_STATE);
    }
    #[test]
    fn the_route_table_is_sent_to_a_client_once_per_change() {
        let mut last = None;
        let frame = |routes: &str| json!({"routing":{"routes":routes,"bgp":"up"}});
        assert_eq!(
            elide_unchanged_routes(frame("a"), &mut last)["routing"]["routes"],
            "a"
        );
        let again = elide_unchanged_routes(frame("a"), &mut last);
        assert_eq!(again["routing"]["routes"], Value::Null);
        assert_eq!(again["routing"]["routes_unchanged"], true);
        assert_eq!(again["routing"]["bgp"], "up");
        assert_eq!(
            elide_unchanged_routes(frame("b"), &mut last)["routing"]["routes"],
            "b"
        );
        // An unavailable table is not "unchanged": the next one is sent in full.
        elide_unchanged_routes(json!({"routing":{}}), &mut last);
        assert_eq!(
            elide_unchanged_routes(frame("b"), &mut last)["routing"]["routes"],
            "b"
        );
    }
    #[tokio::test]
    async fn the_collector_runs_only_while_somebody_is_subscribed() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let samples = Arc::new(AtomicU64::new(0));
        let counter = samples.clone();
        let hub = Arc::new(Hub::with_sampler(
            Duration::from_millis(10),
            move |_| json!({"sample":counter.fetch_add(1, Ordering::SeqCst)}),
        ));
        let mut viewer = hub.subscribe();
        viewer.changed().await.unwrap();
        viewer.changed().await.unwrap();
        drop(viewer);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let idle = samples.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            samples.load(Ordering::SeqCst),
            idle,
            "the collector kept sampling with nobody subscribed"
        );
        assert!(!*hub.running.lock().unwrap());
        // The next viewer starts it again, and is not handed the stale frame.
        let mut viewer = hub.subscribe();
        assert_eq!(viewer.borrow_and_update()["collecting"], true);
        viewer.changed().await.unwrap();
        assert!(viewer.borrow()["sample"].as_u64().unwrap() >= idle);
    }
    #[tokio::test]
    async fn a_stream_rechecks_its_credential_periodically_and_ends_on_revocation() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use tokio_stream::StreamExt;
        let (sender, receiver) = watch::channel(json!({"n":0}));
        let checks = Arc::new(AtomicU64::new(0));
        let counted = checks.clone();
        let mut stream = client_stream_every(receiver, Duration::from_millis(100), move || {
            let n = counted.fetch_add(1, Ordering::SeqCst);
            async move { n < 1 }
        });
        let producer = tokio::spawn(async move {
            for n in 1..200 {
                tokio::time::sleep(Duration::from_millis(5)).await;
                if sender.send(json!({"n":n})).is_err() {
                    return;
                }
            }
        });
        let mut frames = 0;
        let ended = loop {
            match tokio::time::timeout(Duration::from_secs(2), stream.next()).await {
                Ok(Some(Ok(_))) => frames += 1,
                Ok(Some(Err(error))) => break error,
                other => panic!("the stream outlived its revocation: {other:?}"),
            }
        };
        assert_eq!(ended.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(stream.next().await.is_none());
        // Two checks (one passed, one revoked) across many more frames.
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        assert!(frames > 10, "only {frames} frames");
        producer.abort();
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
    /// The default fleet payload carries counters and no endpoint: no state
    /// sample, NAT flow or top talker survives, while the totals do.
    #[test]
    fn fleet_telemetry_without_opt_in_names_no_endpoint() {
        let full = json!({"sequence":1,"interfaces":[{"name":"eth0","rx_bytes":5}],
            "conntrack":{"total":2,"states":[{"src":"192.0.2.7","dst":"198.51.100.9"}],
                "sample_limit":200,"nat_flows":"192.0.2.7:5000 -> 198.51.100.9:443"},
            "top_talkers":"192.0.2.7 9000 bytes","top_talkers_scope":"NAT flows; node-local counters",
            "rule_counters":{"web":3},"errors":{"top_talkers":"192.0.2.7 timed out","routes":"down"}});
        let counters = without_flow_detail(full);
        let text = counters.to_string();
        assert!(
            !text.contains("192.0.2.7") && !text.contains("198.51.100.9"),
            "{text}"
        );
        assert_eq!(counters["conntrack"]["total"], 2);
        assert_eq!(counters["rule_counters"]["web"], 3);
        assert_eq!(counters["interfaces"][0]["rx_bytes"], 5);
        assert_eq!(counters["errors"]["routes"], "down");
        assert_eq!(counters["flow_detail"], false);
    }
}
