// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The PEP: its lifecycle, the control plane, and `decide`.
//!
//! - **`Pep::new`** reads the configuration and the key. Nothing is sent.
//! - **`start`** runs the background work on a thread of its own:
//!   - register (`kind: embedded`, the application, the mode and the
//!     protocol version, iya-sts#2026), again until the service accepts it
//!     and whenever a heartbeat says the PEP is unknown
//!   - `local`: the pull, at `fallbackPollMs` with a signal stream or
//!     `pollIntervalMs` without, at once when an event arrives, and when a
//!     heartbeat says the PEP is not current
//!   - the heartbeat, every `heartbeatIntervalMs`
//!   - the decision records, every few seconds while any are queued
//!   - the key file, read again when it changes
//! - **`decide`** never fails: a decision it can't make is `Unavailable`.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::config::{Mode, PepConfig};
use crate::credential::{Audience, Credential};
use crate::decision::{evaluation_body, obligation_from, Access, Decision, Subject};
use crate::error::PepError;
use crate::http::{Body, Client};
use crate::key::random_id;
use crate::records::Records;

/// The PEP protocol version this crate speaks, sent on registration and
/// heartbeat so the service can refuse one it no longer supports.
pub const PROTOCOL_VERSION: u32 = 1;

/// The Shared Signals event type that says the bound application's
/// policies or the catalogue changed (iya-sts#2028).
pub const POLICIES_CHANGED_EVENT: &str = "urn:iya:sts:secevent:event-type:pep-policies-changed";

/// How often the records are pushed while any are queued.
const RECORDS_INTERVAL: Duration = Duration::from_secs(5);
/// How often the key file is checked.
const KEY_CHECK_INTERVAL: Duration = Duration::from_secs(30);
/// The background loop never sleeps longer than this, so `stop` and an
/// event are prompt even if a notification is missed.
const TICK: Duration = Duration::from_secs(1);
/// A refused or failed registration is tried again after this, doubling up
/// to the heartbeat interval, so a PEP the service refuses (no binding, an
/// unsupported protocol version) doesn't knock every second.
const REGISTER_RETRY_FIRST: Duration = Duration::from_secs(2);

/// Whether the host's signal stream can carry `pep-policies-changed`,
/// reported on the heartbeat (D4) so the console shows a `local` PEP that
/// would never hear of a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStream {
    /// The host has no signal stream (`signals: false`); the PEP polls.
    None,
    /// The stream is running and asked for the event type.
    Requested,
    /// The stream's configuration excludes the event type (the
    /// application's `ssfEvents`).
    Excluded,
    /// The stream is not running or not healthy.
    Down,
}

impl EventStream {
    pub fn as_str(self) -> &'static str {
        match self {
            EventStream::None => "none",
            EventStream::Requested => "requested",
            EventStream::Excluded => "excluded",
            EventStream::Down => "down",
        }
    }
}

/// What the PEP is doing, for a host's health page. Holds no secret.
#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    pub name: String,
    pub mode: Mode,
    pub application: String,
    pub registered: bool,
    pub running: bool,
    /// `local`: a compiled set is held.
    pub holds_policy: bool,
    pub policy_count: usize,
    pub sync_token: String,
    pub decisions: u64,
    pub allowed: u64,
    pub refused: u64,
    pub unavailable: u64,
    pub undischargeable: u64,
    pub records_queued: usize,
    pub key_thumbprint: String,
    /// The current problems, one per area (registration, pull, heartbeat,
    /// records, key), joined; empty when there are none.
    pub last_error: String,

    // ---- Where the PEP is talking to, and how.
    /// The service's base URL, the realm prefix included.
    pub pdp_url: String,
    pub protocol_version: u32,
    /// What the host's signal stream carries, as the heartbeat reports it.
    pub event_stream: EventStream,

    // ---- Times. `None` until the thing has happened (or while the
    // background work is not running, for the `until_` ones).
    /// Since `start`.
    pub uptime: Option<Duration>,
    /// Since what the PEP holds last changed: a new policy set or catalogue
    /// (`local`), a new catalogue (`central`).
    pub since_policy_update: Option<Duration>,
    /// Since the last pull that succeeded, changed or `304`.
    pub since_last_pull: Option<Duration>,
    /// Until the next scheduled pull. An event, or a heartbeat saying the
    /// PEP is stale, pulls sooner.
    pub until_next_pull: Option<Duration>,
    pub since_last_heartbeat: Option<Duration>,
    pub until_next_heartbeat: Option<Duration>,
    /// Since the last `pep-policies-changed` event acted on.
    pub since_last_event: Option<Duration>,

    // ---- What is held.
    /// The catalogue's sync token.
    pub catalogue_token: String,
    /// Subject properties the catalogue declares (the claims that are sent).
    pub catalogue_subject_properties: usize,

    // ---- Counters since `Pep::new`.
    pub pulls: u64,
    /// Pulls that brought something new (the rest were `304`).
    pub pulls_changed: u64,
    pub pull_failures: u64,
    pub heartbeats: u64,
    pub heartbeat_failures: u64,
    pub registrations: u64,
    pub events_received: u64,
    /// Events naming another PEP.
    pub events_ignored: u64,
    pub records_shipped: u64,
    /// Records dropped because the queue was full.
    pub records_dropped: u64,
    /// `central`: Permits held in the cache now, and decisions it answered.
    pub permit_cache_entries: usize,
    pub permit_cache_hits: u64,
    /// The decisions' mean and slowest time, in microseconds (`central`
    /// includes the round trip to the service; `local` the PIP, if asked).
    pub mean_decision_micros: u64,
    pub max_decision_micros: u64,
}

/// When things happened and are due, for `Status`.
#[derive(Default)]
struct Timing {
    started: Option<Instant>,
    last_change: Option<Instant>,
    last_pull: Option<Instant>,
    next_pull: Option<Instant>,
    last_heartbeat: Option<Instant>,
    next_heartbeat: Option<Instant>,
    last_event: Option<Instant>,
}

#[derive(Default)]
struct Counters {
    decisions: AtomicU64,
    allowed: AtomicU64,
    refused: AtomicU64,
    unavailable: AtomicU64,
    undischargeable: AtomicU64,
    pulls: AtomicU64,
    pulls_changed: AtomicU64,
    pull_failures: AtomicU64,
    heartbeats: AtomicU64,
    heartbeat_failures: AtomicU64,
    registrations: AtomicU64,
    events_received: AtomicU64,
    events_ignored: AtomicU64,
    permit_cache_hits: AtomicU64,
    decision_micros_total: AtomicU64,
    decision_micros_max: AtomicU64,
}

#[derive(Default)]
struct Wake {
    pull: bool,
    stop: bool,
}

pub(crate) struct Inner {
    config: PepConfig,
    credential: Credential,
    registered: AtomicBool,
    timing: Mutex<Timing>,
    counters: Counters,
    records: Records,
    problems: Mutex<std::collections::BTreeMap<&'static str, String>>,
    event_stream: Mutex<EventStream>,
    wake: Mutex<Wake>,
    signal: Condvar,
    permits: Mutex<HashMap<String, (Instant, Decision)>>,
    /// `central`: the catalogue's subject properties and its token. The
    /// service refuses an evaluation naming a property its catalogue does
    /// not declare, so only these of a subject's claims are sent.
    subject_roots: RwLock<(String, Arc<HashSet<String>>)>,
    #[cfg(feature = "local")]
    held: RwLock<Option<Arc<crate::local::Held>>>,
    #[cfg(not(feature = "local"))]
    #[allow(dead_code)]
    held: RwLock<Option<()>>,
}

/// The embedded PEP.
pub struct Pep {
    inner: Arc<Inner>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl Pep {
    /// Checks the configuration and reads the key. Sends nothing.
    pub fn new(config: PepConfig) -> Result<Self, PepError> {
        config.validate()?;
        let client = Client::new(&config.tls_ca, Duration::from_millis(config.timeout_ms))?;
        let credential = Credential::new(&config, client)?;
        let instance = random_id();
        let event_stream = if config.signals { EventStream::Requested } else { EventStream::None };
        Ok(Self {
            inner: Arc::new(Inner {
                records: Records::new(instance),
                credential,
                registered: AtomicBool::new(false),
                timing: Mutex::new(Timing::default()),
                counters: Counters::default(),
                problems: Mutex::new(std::collections::BTreeMap::new()),
                event_stream: Mutex::new(event_stream),
                wake: Mutex::new(Wake::default()),
                signal: Condvar::new(),
                permits: Mutex::new(HashMap::new()),
                subject_roots: RwLock::new((String::new(), Arc::new(HashSet::new()))),
                held: RwLock::new(None),
                config,
            }),
            worker: Mutex::new(None),
        })
    }

    /// The configuration in force.
    pub fn config(&self) -> &PepConfig {
        &self.inner.config
    }

    /// The PEP key's RFC 7638 thumbprint. The host library refuses a
    /// configuration where it equals one of its own keys' (D1).
    pub fn key_thumbprint(&self) -> String {
        self.inner.credential.thumbprint()
    }

    /// Reads the key file again now, rather than at the next periodic
    /// check. A changed key drops every token, because each is bound to the
    /// key that asked for it. Returns whether the key changed; a file that
    /// no longer holds a usable key keeps the one held and is an error.
    pub fn reload_key(&self) -> Result<bool, PepError> {
        self.inner.credential.reload_key()
    }

    /// Starts the background work. The first registration and (in `local`)
    /// the first pull are attempted before this returns, so a reachable
    /// service gives a PEP that can decide at once; an unreachable one is
    /// retried in the background, and decisions are `Unavailable` until then.
    pub fn start(&self) -> Result<(), PepError> {
        let mut worker = self.worker.lock().unwrap_or_else(|e| e.into_inner());
        if worker.is_some() {
            return Ok(());
        }
        self.inner.wake.lock().unwrap_or_else(|e| e.into_inner()).stop = false;
        self.inner.timing.lock().unwrap_or_else(|e| e.into_inner()).started = Some(Instant::now());
        self.inner.register();
        self.inner.pull();
        let inner = Arc::clone(&self.inner);
        let handle = std::thread::Builder::new()
            .name(format!("iya-pep {}", self.inner.config.name))
            .spawn(move || inner.run())
            .map_err(|err| PepError::new("config", format!("the PEP's thread could not start: {err}")))?;
        *worker = Some(handle);
        Ok(())
    }

    /// Stops the background work and waits for it. Queued records are sent
    /// once more first.
    pub fn stop(&self) {
        let handle = self.worker.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(handle) = handle {
            self.inner.wake.lock().unwrap_or_else(|e| e.into_inner()).stop = true;
            self.inner.signal.notify_all();
            let _ = handle.join();
        }
    }

    /// Decides one access. Never fails: what can't be decided is
    /// `Unavailable`.
    pub fn decide(&self, subject: &Subject, access: &Access) -> Decision {
        let began = Instant::now();
        let decision = match self.inner.config.mode {
            Mode::Central => self.inner.decide_central(subject, access),
            Mode::Local => self.inner.decide_local(subject, access),
        };
        let c = &self.inner.counters;
        let micros = u64::try_from(began.elapsed().as_micros()).unwrap_or(u64::MAX);
        c.decision_micros_total.fetch_add(micros, Ordering::Relaxed);
        c.decision_micros_max.fetch_max(micros, Ordering::Relaxed);
        c.decisions.fetch_add(1, Ordering::Relaxed);
        match &decision {
            Decision::Permit { .. } => c.allowed.fetch_add(1, Ordering::Relaxed),
            Decision::Deny { .. } => c.refused.fetch_add(1, Ordering::Relaxed),
            Decision::Unavailable { .. } => c.unavailable.fetch_add(1, Ordering::Relaxed),
        };
        decision
    }

    /// Hands over a verified `pep-policies-changed` event: the payload
    /// under [`POLICIES_CHANGED_EVENT`] in the SET's `events`, after the host
    /// library verified the SET as it verifies every other one. The event is
    /// only a hint: `local` pulls with the PEP's own token, and the event's
    /// `sync_token` is never trusted in place of a pull. `central` clears
    /// its Permit cache. An event naming another PEP is ignored. Returns
    /// whether it was acted on.
    pub fn on_policy_event(&self, payload: &Value) -> bool {
        if let Some(pep) = payload.get("pep").and_then(Value::as_str) {
            if pep != self.inner.config.name {
                self.inner.counters.events_ignored.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        self.inner.counters.events_received.fetch_add(1, Ordering::Relaxed);
        self.inner.timing.lock().unwrap_or_else(|e| e.into_inner()).last_event = Some(Instant::now());
        self.inner.permits.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.inner.wake.lock().unwrap_or_else(|e| e.into_inner()).pull = true;
        self.inner.signal.notify_all();
        true
    }

    /// Tells the PEP what the host's signal stream can deliver, for the
    /// heartbeat.
    pub fn set_event_stream(&self, state: EventStream) {
        *self.inner.event_stream.lock().unwrap_or_else(|e| e.into_inner()) = state;
    }

    /// Pulls now and waits for it (`local`). For a host that wants the
    /// policy before it serves its first request.
    pub fn pull_now(&self) -> Result<(), PepError> {
        self.inner.pull_counted().map(|_| ())
    }

    pub fn status(&self) -> Status {
        let inner = &self.inner;
        let c = &inner.counters;
        #[cfg(feature = "local")]
        let (holds_policy, policy_count, sync_token) = match inner.held.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(h) => (true, h.policies.len(), h.policy_token.clone()),
            None => (false, 0, String::new()),
        };
        #[cfg(not(feature = "local"))]
        let (holds_policy, policy_count, sync_token) = (false, 0, String::new());
        let (catalogue_token, catalogue_subject_properties) = inner.catalogue_held();
        let running = self.worker.lock().unwrap_or_else(|e| e.into_inner()).is_some();
        let t = inner.timing.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let since = |at: Option<Instant>| at.map(|at| now.saturating_duration_since(at));
        let until = |at: Option<Instant>| at.map(|at| at.saturating_duration_since(now));
        let (shipped, dropped) = inner.records.counts();
        let decisions = c.decisions.load(Ordering::Relaxed);
        Status {
            name: inner.config.name.clone(),
            mode: inner.config.mode,
            application: inner.config.application.clone(),
            registered: inner.registered.load(Ordering::Relaxed),
            running,
            holds_policy,
            policy_count,
            sync_token,
            decisions: c.decisions.load(Ordering::Relaxed),
            allowed: c.allowed.load(Ordering::Relaxed),
            refused: c.refused.load(Ordering::Relaxed),
            unavailable: c.unavailable.load(Ordering::Relaxed),
            undischargeable: c.undischargeable.load(Ordering::Relaxed),
            records_queued: inner.records.queued(),
            key_thumbprint: inner.credential.thumbprint(),
            last_error: inner.problems.lock().unwrap_or_else(|e| e.into_inner()).values().cloned().collect::<Vec<_>>().join("; "),
            pdp_url: inner.config.base().to_string(),
            protocol_version: PROTOCOL_VERSION,
            event_stream: *inner.event_stream.lock().unwrap_or_else(|e| e.into_inner()),
            uptime: since(t.started),
            since_policy_update: since(t.last_change),
            since_last_pull: since(t.last_pull),
            until_next_pull: if running { until(t.next_pull) } else { None },
            since_last_heartbeat: since(t.last_heartbeat),
            until_next_heartbeat: if running { until(t.next_heartbeat) } else { None },
            since_last_event: since(t.last_event),
            catalogue_token,
            catalogue_subject_properties,
            pulls: c.pulls.load(Ordering::Relaxed),
            pulls_changed: c.pulls_changed.load(Ordering::Relaxed),
            pull_failures: c.pull_failures.load(Ordering::Relaxed),
            heartbeats: c.heartbeats.load(Ordering::Relaxed),
            heartbeat_failures: c.heartbeat_failures.load(Ordering::Relaxed),
            registrations: c.registrations.load(Ordering::Relaxed),
            events_received: c.events_received.load(Ordering::Relaxed),
            events_ignored: c.events_ignored.load(Ordering::Relaxed),
            records_shipped: shipped,
            records_dropped: dropped,
            permit_cache_entries: inner.permits.lock().unwrap_or_else(|e| e.into_inner()).len(),
            permit_cache_hits: c.permit_cache_hits.load(Ordering::Relaxed),
            mean_decision_micros: c.decision_micros_total.load(Ordering::Relaxed).checked_div(decisions).unwrap_or(0),
            max_decision_micros: c.decision_micros_max.load(Ordering::Relaxed),
        }
    }
}

impl Drop for Pep {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Inner {
    fn base(&self) -> &str {
        self.config.base()
    }

    /// The catalogue's token and how many subject properties it declares:
    /// the held set's in `local`, the one pulled for its claims in `central`.
    fn catalogue_held(&self) -> (String, usize) {
        #[cfg(feature = "local")]
        if let Some(h) = self.held.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            let roots: HashSet<String> = h.catalogue.rows.iter().filter(|r| r.object == "subject").map(|r| root_of(&r.property)).collect();
            return (h.catalogue_token.clone(), roots.len());
        }
        let roots = self.subject_roots.read().unwrap_or_else(|e| e.into_inner());
        (roots.0.clone(), roots.1.len())
    }

    /// Records the problem of one area, or clears it with an empty one.
    fn note(&self, area: &'static str, problem: &str) {
        let mut problems = self.problems.lock().unwrap_or_else(|e| e.into_inner());
        if problem.is_empty() {
            problems.remove(area);
        } else {
            problems.insert(area, problem.to_string());
        }
    }

    fn identity(&self) -> Value {
        json!({
            "name": self.config.name,
            "kind": "embedded",
            "application": self.config.application,
            "mode": self.config.mode.as_str(),
            "protocolVersion": PROTOCOL_VERSION,
            "version": concat!("iya-pep-rust/", env!("CARGO_PKG_VERSION")),
        })
    }

    fn register(&self) {
        let url = format!("{}/xacml/pep/register", self.base());
        match self.credential.call(Audience::Pep, "POST", &url, "application/json", &[], Some(&Body::Json(&self.identity()))) {
            Ok(answer) if answer.status == 200 || answer.status == 201 => {
                self.counters.registrations.fetch_add(1, Ordering::Relaxed);
                self.registered.store(true, Ordering::Relaxed);
                self.note("register", "");
            }
            Ok(answer) => {
                let json = answer.json().unwrap_or(Value::Null);
                self.note("register", &format!(
                    "registration answered {} {} {}",
                    answer.status,
                    json["error"].as_str().unwrap_or(""),
                    json["error_description"].as_str().unwrap_or("")
                ));
            }
            Err(err) => self.note("register", &format!("registration: {err}")),
        }
    }

    /// One heartbeat. Returns whether the service says the PEP is not
    /// current (a pull is due).
    fn heartbeat(&self) -> bool {
        let url = format!("{}/xacml/pep/heartbeat", self.base());
        let c = &self.counters;
        let mut body = self.identity();
        #[cfg(feature = "local")]
        if let Some(h) = self.held.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            body["syncToken"] = json!(h.policy_token);
            body["policyCount"] = json!(h.policies.len());
        }
        body["decisions"] = json!(c.decisions.load(Ordering::Relaxed));
        body["allowed"] = json!(c.allowed.load(Ordering::Relaxed));
        body["refused"] = json!(c.refused.load(Ordering::Relaxed) + c.unavailable.load(Ordering::Relaxed));
        body["undischargeable"] = json!(c.undischargeable.load(Ordering::Relaxed));
        body["policyEvents"] = json!(self.event_stream.lock().unwrap_or_else(|e| e.into_inner()).as_str());
        let answer = self.credential.call(Audience::Pep, "POST", &url, "application/json", &[], Some(&Body::Json(&body)));
        if matches!(&answer, Ok(a) if a.status == 200) {
            self.counters.heartbeats.fetch_add(1, Ordering::Relaxed);
            self.timing.lock().unwrap_or_else(|e| e.into_inner()).last_heartbeat = Some(Instant::now());
        } else {
            self.counters.heartbeat_failures.fetch_add(1, Ordering::Relaxed);
        }
        match answer {
            Ok(answer) if answer.status == 200 => {
                self.note("heartbeat", "");
                answer.json().is_some_and(|j| j["current"] == json!(false))
            }
            Ok(answer) if answer.status == 404 => {
                self.registered.store(false, Ordering::Relaxed);
                false
            }
            Ok(answer) => {
                self.note("heartbeat", &format!("the heartbeat answered {}", answer.status));
                false
            }
            Err(err) => {
                self.note("heartbeat", &format!("the heartbeat: {err}"));
                false
            }
        }
    }

    /// `local`: the policies and the catalogue. `central`: the catalogue
    /// alone, for the subject properties it declares.
    /// Returns whether anything new is held.
    fn pull_result(&self) -> Result<bool, PepError> {
        #[cfg(feature = "local")]
        if self.config.mode == Mode::Local {
            let current = self.held.read().unwrap_or_else(|e| e.into_inner()).clone();
            let (_, fresh) = crate::local::pull(&self.credential, self.base(), &self.config.name, current.as_ref())?;
            let changed = fresh.is_some();
            if let Some(fresh) = fresh {
                *self.held.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(fresh));
            }
            return Ok(changed);
        }
        let token = self.subject_roots.read().unwrap_or_else(|e| e.into_inner()).0.clone();
        let fresh = crate::decision::pull_subject_roots(&self.credential, self.base(), &token)?;
        let changed = fresh.is_some();
        if let Some(fresh) = fresh {
            *self.subject_roots.write().unwrap_or_else(|e| e.into_inner()) = (fresh.0, Arc::new(fresh.1));
        }
        Ok(changed)
    }

    /// `pull_result`, counted and timed for `Status`.
    fn pull_counted(&self) -> Result<bool, PepError> {
        let result = self.pull_result();
        let now = Instant::now();
        match &result {
            Ok(changed) => {
                self.counters.pulls.fetch_add(1, Ordering::Relaxed);
                let mut t = self.timing.lock().unwrap_or_else(|e| e.into_inner());
                t.last_pull = Some(now);
                if *changed {
                    self.counters.pulls_changed.fetch_add(1, Ordering::Relaxed);
                    t.last_change = Some(now);
                }
            }
            Err(_) => {
                self.counters.pull_failures.fetch_add(1, Ordering::Relaxed);
            }
        }
        result
    }

    fn pull(&self) {
        match self.pull_counted() {
            Ok(_) => self.note("pull", ""),
            Err(err) => self.note("pull", &format!("the pull: {err}")),
        }
    }

    fn run(self: Arc<Self>) {
        let now = Instant::now();
        let mut next_heartbeat = now;
        let mut next_records = now + RECORDS_INTERVAL;
        let mut next_key = now + KEY_CHECK_INTERVAL;
        let mut next_register = now;
        let mut register_retry = REGISTER_RETRY_FIRST;
        let register_retry_max = Duration::from_millis(self.config.heartbeat_interval_ms).max(REGISTER_RETRY_FIRST);
        let poll = Duration::from_millis(if self.config.signals { self.config.fallback_poll_ms } else { self.config.poll_interval_ms });
        let mut next_pull = now + poll;
        loop {
            let pull_asked = {
                let mut wake = self.wake.lock().unwrap_or_else(|e| e.into_inner());
                if !wake.stop && !wake.pull {
                    wake = self.signal.wait_timeout(wake, TICK).map(|(g, _)| g).unwrap_or_else(|e| e.into_inner().0);
                }
                if wake.stop {
                    break;
                }
                std::mem::take(&mut wake.pull)
            };
            let now = Instant::now();
            if now >= next_key {
                next_key = now + KEY_CHECK_INTERVAL;
                match self.credential.reload_key() {
                    Ok(_) => self.note("key", ""),
                    Err(err) => self.note("key", &format!("the assertion key: {err}")),
                }
            }
            if !self.registered.load(Ordering::Relaxed) && now >= next_register {
                self.register();
                if self.registered.load(Ordering::Relaxed) {
                    register_retry = REGISTER_RETRY_FIRST;
                } else {
                    next_register = now + register_retry;
                    register_retry = (register_retry * 2).min(register_retry_max);
                }
            }
            let mut pull_due = pull_asked || now >= next_pull;
            if now >= next_heartbeat {
                next_heartbeat = now + Duration::from_millis(self.config.heartbeat_interval_ms);
                pull_due |= self.heartbeat();
            }
            if pull_due {
                next_pull = Instant::now() + poll;
                self.pull();
            }
            if now >= next_records {
                next_records = now + RECORDS_INTERVAL;
                self.ship_records();
            }
            {
                let mut t = self.timing.lock().unwrap_or_else(|e| e.into_inner());
                t.next_pull = Some(next_pull);
                t.next_heartbeat = Some(next_heartbeat);
            }
        }
        self.ship_records();
    }

    fn ship_records(&self) {
        if self.records.queued() == 0 {
            return;
        }
        let url = format!("{}/admin-api/pep-audit", self.base());
        match self.records.ship(&self.credential, &url) {
            Ok(_) => self.note("records", ""),
            Err(err) => self.note("records", &format!("the decision records: {err}")),
        }
    }

    fn decide_central(&self, subject: &Subject, access: &Access) -> Decision {
        let roots = self.subject_roots.read().unwrap_or_else(|e| e.into_inner()).1.clone();
        let body = evaluation_body(&declared_only(subject, &roots), access, &self.config.application, &self.config.supported_obligations);
        let cache_for = Duration::from_millis(self.config.permit_cache_ms);
        let cache_key = body.to_string();
        if !cache_for.is_zero() {
            let mut permits = self.permits.lock().unwrap_or_else(|e| e.into_inner());
            match permits.get(&cache_key) {
                Some((at, decision)) if at.elapsed() < cache_for => {
                    self.counters.permit_cache_hits.fetch_add(1, Ordering::Relaxed);
                    return decision.clone();
                }
                Some(_) => {
                    permits.remove(&cache_key);
                }
                None => {}
            }
        }
        let url = format!("{}/access/v1/evaluation", self.base());
        let answer = match self.credential.call(Audience::Access, "POST", &url, "application/json", &[], Some(&Body::Json(&body))) {
            Ok(answer) => answer,
            Err(err) => return Decision::Unavailable { why: format!("the service could not be asked: {err}") },
        };
        let json = answer.json().unwrap_or(Value::Null);
        let decision = match (answer.status, json.get("decision").and_then(Value::as_bool)) {
            (200, Some(true)) => Decision::Permit {
                obligations: json["context"]["obligations"].as_array().map(|list| list.iter().filter_map(obligation_from).collect()).unwrap_or_default(),
                advice: Vec::new(),
            },
            (200, Some(false)) => {
                if json["context"]["undischargeable_obligations"].as_array().is_some_and(|l| !l.is_empty()) {
                    self.counters.undischargeable.fetch_add(1, Ordering::Relaxed);
                }
                Decision::Deny { why: reason(&json).unwrap_or_else(|| "the service denied the access".into()) }
            }
            (400, _) => Decision::Deny {
                why: format!(
                    "the service refused the evaluation: {} {}",
                    json["error"].as_str().or(json["code"].as_str()).unwrap_or(""),
                    json["error_description"].as_str().or(json["message"].as_str()).unwrap_or("")
                )
                .trim_end()
                .to_string(),
            },
            (status, _) => Decision::Unavailable { why: format!("the service answered {status} to the evaluation") },
        };
        if !cache_for.is_zero() && decision.is_permit() {
            self.permits.lock().unwrap_or_else(|e| e.into_inner()).insert(cache_key, (Instant::now(), decision.clone()));
        }
        decision
    }

    #[cfg(not(feature = "local"))]
    fn decide_local(&self, _subject: &Subject, _access: &Access) -> Decision {
        Decision::Unavailable { why: "this build has no engine (the iya-pep `local` feature)".into() }
    }

    #[cfg(feature = "local")]
    fn decide_local(&self, subject: &Subject, access: &Access) -> Decision {
        let Some(held) = self.held.read().unwrap_or_else(|e| e.into_inner()).clone() else {
            return Decision::Unavailable { why: "no policy is held yet".into() };
        };
        let roots: HashSet<String> = held.catalogue.rows.iter().filter(|r| r.object == "subject").map(|r| root_of(&r.property)).collect();
        let body = evaluation_body(&declared_only(subject, &roots), access, &self.config.application, &self.config.supported_obligations);
        let trusted = crate::authzen::Trusted { realm: self.config.realm(), caller: self.config.name.clone(), application: self.config.application.clone() };
        let made = crate::local::decide(&self.credential, self.base(), &held, &body, &trusted, &subject.id, subject.kind == "application", std::time::SystemTime::now());
        if let Some(outcome) = &made.outcome {
            if !outcome.undischargeable.is_empty() {
                self.counters.undischargeable.fetch_add(1, Ordering::Relaxed);
            }
            if self.config.decision_records {
                self.records.push(json!({
                    "kind": "authzen",
                    "endpoint": "evaluation",
                    "decision": outcome.xacml_decision.as_str(),
                    "allowed": made.decision.is_permit(),
                    "fault": outcome.fault,
                    "subject": subject.id,
                    "subjectType": subject.kind,
                    "resource": format!("{}:{}", access.resource_type, access.resource_id),
                    "action": access.action,
                    "application": self.config.application,
                    "caller": self.config.name,
                    "bias": "deny-biased",
                    "why": outcome.why,
                    "discharged": outcome.discharged,
                    "undischargeable": outcome.undischargeable,
                }));
            }
        }
        made.decision
    }
}

/// A dotted property path's first segment.
pub(crate) fn root_of(property: &str) -> String {
    property.split('.').next().unwrap_or("").to_string()
}

/// `subject` with only the properties the catalogue declares. The service
/// refuses an evaluation that names any other (STS-AUTHZEN-0004), so a
/// host may hand every claim it has.
fn declared_only(subject: &Subject, roots: &HashSet<String>) -> Subject {
    let mut out = subject.clone();
    out.properties.retain(|name, _| roots.contains(name));
    out
}

fn reason(json: &Value) -> Option<String> {
    let context = json.get("context")?;
    for key in ["reason_admin", "reason_user"] {
        match context.get(key) {
            Some(Value::String(s)) if !s.is_empty() => return Some(s.clone()),
            Some(Value::Object(map)) => {
                if let Some(text) = map.values().find_map(Value::as_str) {
                    return Some(text.to_string());
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(feature = "tokio")]
mod async_api {
    use super::*;

    async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Result<T, PepError> {
        tokio::task::spawn_blocking(work).await.map_err(|err| PepError::new("transport", format!("the blocking call did not complete: {err}")))
    }

    impl Pep {
        /// `start`, off the runtime's threads.
        pub async fn start_async(self: &Arc<Self>) -> Result<(), PepError> {
            let pep = Arc::clone(self);
            blocking(move || pep.start()).await?
        }

        /// `decide`, off the runtime's threads (`central` is a network call,
        /// and `local` may ask the PIP).
        pub async fn decide_async(self: &Arc<Self>, subject: Subject, access: Access) -> Decision {
            let pep = Arc::clone(self);
            blocking(move || pep.decide(&subject, &access)).await.unwrap_or_else(|err| Decision::Unavailable { why: err.message })
        }

        /// `stop`, off the runtime's threads.
        pub async fn stop_async(self: &Arc<Self>) {
            let pep = Arc::clone(self);
            let _ = blocking(move || pep.stop()).await;
        }
    }
}
