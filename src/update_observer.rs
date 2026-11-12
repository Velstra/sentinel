//! One non-queuing observation and admission per API instance. A request owns
//! neither the background observation nor its capacity: blocking work keeps
//! its owned permit until it really returns, even after HTTP cancellation.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::update_jobs::{self, Code, Error, JobView, Status};

const REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const FRESH_FOR: Duration = Duration::from_secs(5);

#[cfg(test)]
type FixtureCollector = Arc<dyn Fn() -> Result<Status, Error> + Send + Sync>;

#[derive(Default)]
struct Gate(Arc<AtomicBool>);

pub(crate) struct Permit(Arc<AtomicBool>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Gate {
    fn enter(&self) -> Option<Permit> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Permit(Arc::clone(&self.0)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Freshness {
    Initializing,
    Fresh,
    Refreshing,
    Stale,
    Unavailable,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Observation {
    pub state: Freshness,
    pub age_ms: Option<u64>,
    pub refresh_in_progress: bool,
    pub reason: Option<&'static str>,
}

#[derive(Serialize)]
pub(crate) struct View {
    #[serde(flatten)]
    pub status: Status,
    pub observation: Observation,
}

#[derive(Serialize)]
pub(crate) struct JobReply {
    #[serde(flatten)]
    pub job: JobView,
    pub observation: Observation,
}

#[derive(Default)]
struct Cache {
    value: Option<Status>,
    observed_at: Option<Instant>,
    started_at: Option<Instant>,
    running: bool,
    error: Option<Code>,
    invalidated: bool,
    revision: u64,
    exhausted: bool,
}

#[derive(Default)]
pub(crate) struct Observer {
    cache: Mutex<Cache>,
    observation_gate: Gate,
    admission_gate: Gate,
    #[cfg(test)]
    fixture_collector: Mutex<Option<FixtureCollector>>,
}

struct Refresh {
    observer: Arc<Observer>,
    revision: u64,
    completed: bool,
    // Never move this permit into the request/JoinHandle/deadline future.
    _permit: Permit,
}
impl Drop for Refresh {
    fn drop(&mut self) {
        if let Ok(mut cache) = self.observer.cache.lock() {
            cache.running = false;
            if !self.completed && cache.revision == self.revision {
                cache.error = Some(Code::StateUnavailable);
            }
        }
    }
}

impl Refresh {
    fn run<F>(mut self, collect: F)
    where
        F: FnOnce() -> Result<Status, Error>,
    {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(collect))
            .unwrap_or(Err(Error(Code::StateUnavailable)));
        if let Ok(mut cache) = self.observer.cache.lock() {
            if cache.revision == self.revision && !cache.exhausted {
                match result {
                    Ok(value) => {
                        cache.value = Some(value);
                        cache.observed_at = Some(Instant::now());
                        cache.error = None;
                        cache.invalidated = false;
                    }
                    Err(error) => cache.error = Some(error.0),
                }
            }
        }
        self.completed = true;
        // This consumes the WHOLE guard, including its permit; closure capture
        // cannot separate the permit lifetime from the actual blocking work.
    }
}

impl Observer {
    #[cfg(test)]
    pub(crate) fn set_fixture_collector(&self, collect: FixtureCollector) {
        *self.fixture_collector.lock().unwrap() = Some(collect);
    }

    pub(crate) fn admit(&self) -> Result<Permit, Error> {
        self.admission_gate.enter().ok_or(Error(Code::Busy))
    }

    pub(crate) fn invalidate(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.invalidated = true;
            if let Some(next) = cache.revision.checked_add(1) {
                cache.revision = next;
            } else {
                // Permanent unknown state is safer than recycling a generation.
                cache.error = Some(Code::StateUnavailable);
                cache.value = None;
                cache.exhausted = true;
            }
        }
    }

    pub(crate) fn observe(self: &Arc<Self>, config: PathBuf, apply: bool, write: bool) -> View {
        #[cfg(test)]
        {
            let collect = self.fixture_collector.lock().unwrap().clone();
            if let Some(collect) = collect {
                return self.observe_with(write, move || collect());
            }
        }
        // Off-box/no-apply inspection must not create files, activate a machine
        // or consume a background task merely to report an unsupported runtime.
        if !apply
            || unsafe { libc::geteuid() } != 0
            || config != Path::new(crate::session::DEFAULT_CONFIG)
        {
            return View {
                status: update_jobs::unavailable_status(Code::UnsupportedRuntime),
                observation: Observation {
                    state: Freshness::Fresh,
                    age_ms: Some(0),
                    refresh_in_progress: false,
                    reason: None,
                },
            };
        }
        self.observe_with(write, move || update_jobs::status(&config, apply, true))
    }

    fn observe_with<F>(self: &Arc<Self>, write: bool, collect: F) -> View
    where
        F: FnOnce() -> Result<Status, Error> + Send + 'static,
    {
        self.schedule(collect);
        self.view(write, Instant::now())
    }

    fn schedule<F>(self: &Arc<Self>, collect: F)
    where
        F: FnOnce() -> Result<Status, Error> + Send + 'static,
    {
        // Acquire BEFORE spawning. Contention never queues another task.
        let Some(permit) = self.observation_gate.enter() else {
            return;
        };
        let revision = {
            let Ok(mut cache) = self.cache.lock() else {
                return;
            };
            let now = Instant::now();
            if cache.exhausted
                || cache
                    .started_at
                    .is_some_and(|last| now.saturating_duration_since(last) < REFRESH_INTERVAL)
            {
                return;
            }
            cache.started_at = Some(now);
            cache.running = true;
            cache.revision
        };
        let refresh = Refresh {
            observer: Arc::clone(self),
            revision,
            completed: false,
            _permit: permit,
        };
        drop(tokio::task::spawn_blocking(move || refresh.run(collect)));
    }

    fn view(&self, write: bool, now: Instant) -> View {
        let Ok(cache) = self.cache.lock() else {
            return View {
                status: update_jobs::unavailable_status(Code::StateUnavailable),
                observation: Observation {
                    state: Freshness::Unavailable,
                    age_ms: None,
                    refresh_in_progress: false,
                    reason: Some("Protected update observation is unavailable."),
                },
            };
        };
        let age = cache
            .observed_at
            .map(|at| now.saturating_duration_since(at));
        let state = if cache.value.is_some() {
            if cache.invalidated
                || cache.error.is_some()
                || age.is_none_or(|value| value > FRESH_FOR)
            {
                Freshness::Stale
            } else if cache.running {
                Freshness::Refreshing
            } else {
                Freshness::Fresh
            }
        } else if cache.error.is_some()
            || cache
                .started_at
                .is_some_and(|at| now.saturating_duration_since(at) > FRESH_FOR)
        {
            Freshness::Unavailable
        } else {
            Freshness::Initializing
        };
        let mut status = cache
            .value
            .clone()
            .unwrap_or_else(|| update_jobs::unavailable_status(Code::StateUnavailable));
        if !write || state != Freshness::Fresh {
            status.can_check = false;
            status.can_stage = false;
            status.mutation_context = None;
        }
        if let Some(error) = cache.error {
            status.unavailable = Some(error);
        }
        View {
            status,
            observation: Observation {
                state,
                age_ms: age.map(|value| value.as_millis().min(u64::MAX as u128) as u64),
                refresh_in_progress: cache.running,
                reason: match state {
                    Freshness::Initializing => Some("Waiting for the first update observation."),
                    Freshness::Fresh => None,
                    Freshness::Refreshing => {
                        Some("Refreshing update observations; actions wait for completion.")
                    }
                    Freshness::Stale => {
                        Some("The last observation is stale; update actions are disabled.")
                    }
                    Freshness::Unavailable => {
                        Some("Update observation is unavailable; no update was authorized.")
                    }
                },
            },
        }
    }

    pub(crate) fn job(
        self: &Arc<Self>,
        config: PathBuf,
        apply: bool,
        id: &str,
    ) -> Result<JobReply, Error> {
        if !update_jobs::is_id(id) {
            return Err(Error(Code::InvalidRequest));
        }
        let view = self.observe(config, apply, false);
        if let Some(job) = view.status.jobs.into_iter().find(|job| job.id == id) {
            return Ok(JobReply {
                job,
                observation: view.observation,
            });
        }
        if view.status.unavailable == Some(Code::UnsupportedRuntime) {
            return Err(Error(Code::UnsupportedRuntime));
        }
        // A cold/stale cache cannot truthfully declare a newly accepted job
        // missing. The caller keeps its request ID and retries observation.
        Err(Error(
            if view.observation.state == Freshness::Fresh && view.status.generation.is_some() {
                Code::NotFound
            } else {
                Code::StateUnavailable
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_jobs::Snapshot;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;

    fn sample(generation: &str) -> Status {
        let snapshot = Snapshot {
            boot_id: "12345678-1234-1234-1234-123456789abc".into(),
            mutation_epoch: "9".repeat(64),
            config_revision: "f".repeat(64),
            public_key_sha256: "b".repeat(64),
            release: "2.0.1".into(),
            slot: "sentinel-a".into(),
            verity: "c".repeat(64),
            selected_entry: "sentinel-a.efi".into(),
            next_entry: "sentinel-a.efi".into(),
            uki_sha256: "d".repeat(64),
            verity_guid: "22222222-2222-2222-2222-222222222222".into(),
            store_guid: "33333333-3333-3333-3333-333333333333".into(),
            permanent: true,
        };
        Status {
            schema: 1,
            generation: Some(generation.into()),
            current: Some((&snapshot).into()),
            mutation_context: Some(snapshot),
            offer: None,
            jobs: Vec::new(),
            can_check: true,
            can_stage: true,
            unavailable: None,
        }
    }

    fn seeded() -> Arc<Observer> {
        let observer = Arc::new(Observer::default());
        {
            let mut cache = observer.cache.lock().unwrap();
            cache.value = Some(sample("known"));
            cache.observed_at = Some(Instant::now());
        }
        observer
    }

    async fn idle(observer: &Observer, observation: bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            let gate = if observation {
                &observer.observation_gate
            } else {
                &observer.admission_gate
            };
            while gate.0.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("owned work did not release its permit");
    }

    async fn wait_entered(receiver: &mpsc::Receiver<()>) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match receiver.try_recv() {
                    Ok(()) => return,
                    Err(mpsc::TryRecvError::Empty) => {
                        tokio::time::sleep(Duration::from_millis(1)).await
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        panic!("work ended before entering its barrier")
                    }
                }
            }
        })
        .await
        .expect("work did not enter its barrier");
    }

    #[test]
    fn observer_initial_state_is_not_a_healthy_sample_or_write_context() {
        let observer = Observer::default();
        let view = observer.view(true, Instant::now());
        assert_eq!(view.observation.state, Freshness::Initializing);
        assert!(view.status.current.is_none() && view.status.mutation_context.is_none());
        assert!(!view.status.can_check && !view.status.can_stage);
    }

    #[test]
    fn observer_redacts_each_readonly_response_without_mutating_cached_writable_facts() {
        let observer = seeded();
        for _ in 0..200 {
            let readonly = observer.view(false, Instant::now());
            assert!(!readonly.status.can_check && !readonly.status.can_stage);
            assert!(readonly.status.mutation_context.is_none());
            assert!(
                !serde_json::to_string(&readonly)
                    .unwrap()
                    .contains(&"f".repeat(64))
            );
            let writable = observer.view(true, Instant::now());
            assert!(writable.status.can_check && writable.status.can_stage);
            assert!(writable.status.mutation_context.is_some());
        }
    }

    #[test]
    fn observer_stale_known_facts_remain_visible_but_never_authorize_writes() {
        let observer = seeded();
        let view = observer.view(true, Instant::now() + FRESH_FOR + Duration::from_secs(1));
        assert_eq!(view.observation.state, Freshness::Stale);
        assert!(view.status.current.is_some());
        assert!(!view.status.can_check && !view.status.can_stage);
        assert!(view.status.mutation_context.is_none());
    }

    #[tokio::test]
    async fn observer_poll_flood_and_elapsed_deadline_never_queue_replacement_work() {
        let observer = Arc::new(Observer::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        let (entered, started) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let first = observer.observe_with(true, move || {
            called.fetch_add(1, Ordering::SeqCst);
            entered.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok(sample("first"))
        });
        assert!(!first.status.can_stage);
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        observer.cache.lock().unwrap().started_at =
            Some(Instant::now() - FRESH_FOR - Duration::from_secs(1));
        for _ in 0..1000 {
            let view =
                observer.observe_with(true, || panic!("a poll queued extra observation work"));
            assert_eq!(view.observation.state, Freshness::Unavailable);
            assert!(view.observation.refresh_in_progress);
            assert!(!view.status.can_check && !view.status.can_stage);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Observation congestion is not admission/configuration ownership.
        drop(observer.admit().unwrap());
        release.send(()).unwrap();
        idle(&observer, true).await;
        assert_eq!(
            observer
                .view(true, Instant::now())
                .status
                .generation
                .as_deref(),
            Some("first")
        );
    }

    #[tokio::test]
    async fn observer_cooldown_is_not_bypassed_by_invalidation_or_polling() {
        let observer = Arc::new(Observer::default());
        observer.observe_with(true, || Ok(sample("first")));
        idle(&observer, true).await;
        observer.invalidate();
        for _ in 0..100 {
            let view =
                observer.observe_with(true, || panic!("refresh ignored its minimum interval"));
            assert_eq!(view.observation.state, Freshness::Stale);
        }
        assert!(!observer.observation_gate.0.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn observer_late_completion_cannot_overwrite_a_newer_cache_revision() {
        let observer = seeded();
        let (entered, started) = mpsc::channel();
        let (release, released) = mpsc::channel();
        observer.observe_with(true, move || {
            entered.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok(sample("obsolete"))
        });
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        observer.invalidate();
        release.send(()).unwrap();
        idle(&observer, true).await;
        let view = observer.view(true, Instant::now());
        assert_eq!(view.status.generation.as_deref(), Some("known"));
        assert_eq!(view.observation.state, Freshness::Stale);
        observer.cache.lock().unwrap().started_at = Some(Instant::now() - REFRESH_INTERVAL);
        observer.observe_with(true, || Ok(sample("new")));
        idle(&observer, true).await;
        assert_eq!(
            observer
                .view(true, Instant::now())
                .status
                .generation
                .as_deref(),
            Some("new")
        );
    }

    #[tokio::test]
    async fn observer_failure_or_panic_is_unavailable_not_an_empty_healthy_sample() {
        let observer = seeded();
        observer.observe_with(true, || Err(Error(Code::MetadataRefused)));
        idle(&observer, true).await;
        let view = observer.view(true, Instant::now());
        assert_eq!(view.observation.state, Freshness::Stale);
        assert_eq!(view.status.unavailable, Some(Code::MetadataRefused));
        assert!(view.status.mutation_context.is_none());
        let cold = Arc::new(Observer::default());
        cold.observe_with(true, || panic!("controlled observer panic"));
        idle(&cold, true).await;
        assert_eq!(
            cold.view(true, Instant::now()).observation.state,
            Freshness::Unavailable
        );
    }

    #[tokio::test]
    async fn observer_admission_permit_survives_http_task_abort_until_real_work_returns() {
        let observer = Arc::new(Observer::default());
        let permit = observer.admit().unwrap();
        let (entered, started) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let request = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                entered.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(2)).unwrap();
            })
            .await
            .unwrap();
        });
        wait_entered(&started).await;
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert!(matches!(observer.admit(), Err(Error(Code::Busy))));
        release.send(()).unwrap();
        idle(&observer, false).await;
        drop(observer.admit().unwrap());
    }

    #[tokio::test]
    async fn observer_admission_timeout_does_not_release_a_still_running_permit() {
        let observer = Arc::new(Observer::default());
        let permit = observer.admit().unwrap();
        let (entered, started) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let admission = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            entered.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            tokio::time::timeout(Duration::ZERO, admission)
                .await
                .is_err()
        );
        assert!(matches!(observer.admit(), Err(Error(Code::Busy))));
        release.send(()).unwrap();
        idle(&observer, false).await;
    }

    #[tokio::test]
    async fn observer_exhausted_revision_and_poisoned_cache_fail_closed() {
        let observer = seeded();
        observer.cache.lock().unwrap().revision = u64::MAX;
        observer.invalidate();
        let view = observer.observe_with(true, || panic!("exhausted cache launched work"));
        assert_eq!(view.observation.state, Freshness::Unavailable);
        assert!(view.status.current.is_none());
        let poisoned = Arc::new(Observer::default());
        let copy = Arc::clone(&poisoned);
        assert!(
            std::thread::spawn(move || {
                let _cache = copy.cache.lock().unwrap();
                panic!("controlled cache poisoning");
            })
            .join()
            .is_err()
        );
        assert_eq!(
            poisoned
                .observe_with(true, || panic!("poisoned cache launched work"))
                .observation
                .state,
            Freshness::Unavailable
        );
    }
}
