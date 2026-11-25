// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! Decision records: what a `local` PEP decided in process, pushed to
//! `POST /admin-api/pep-audit` with the PEP's `xacml:pep-audit` token, so
//! each one is a row of the service's audit log. A `central` decision is the
//! service's and recorded there, so it is never sent again from here.
//!
//! Delivery is at least once: a record leaves the queue only when the
//! service acknowledges its `seq`. The queue is bounded, and the oldest
//! record is dropped (and counted) when it is full.

use std::collections::VecDeque;
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::credential::{Audience, Credential};
use crate::error::PepError;
use crate::http::Body;

/// The most records a push carries (the service's limit).
pub const BATCH: usize = 500;
/// The most records held while the service can't be reached.
pub const BUFFER: usize = 10_000;

#[derive(Default)]
struct State {
    queue: VecDeque<Value>,
    seq: u64,
    dropped: u64,
    shipped: u64,
}

/// The queue.
pub struct Records {
    instance: String,
    state: Mutex<State>,
}

impl Records {
    pub fn new(instance: String) -> Self {
        Self { instance, state: Mutex::new(State::default()) }
    }

    /// Queues one record; `seq` and `at` are added here.
    pub fn push(&self, mut record: Value) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.seq += 1;
        record["seq"] = json!(state.seq);
        record["at"] = json!(now_rfc3339());
        if state.queue.len() >= BUFFER {
            state.queue.pop_front();
            state.dropped += 1;
        }
        state.queue.push_back(record);
    }

    pub fn queued(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).queue.len()
    }

    /// (shipped, dropped)
    pub fn counts(&self) -> (u64, u64) {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        (state.shipped, state.dropped)
    }

    /// Pushes one batch. Records up to the acknowledged `seq` leave the
    /// queue.
    pub fn ship(&self, credential: &Credential, url: &str) -> Result<usize, PepError> {
        let batch: Vec<Value> = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.queue.iter().take(BATCH).cloned().collect()
        };
        if batch.is_empty() {
            return Ok(0);
        }
        let body = json!({"instance": self.instance, "events": batch});
        let answer = credential.call(Audience::Audit, "POST", url, "application/json", &[], Some(&Body::Json(&body)))?;
        if answer.status != 200 {
            return Err(PepError::new("refused", format!("{url} answered {}: {}", answer.status, answer.body.chars().take(200).collect::<String>())));
        }
        let acknowledged = answer.json().and_then(|j| j["acknowledged"].as_u64()).unwrap_or(0);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let before = state.queue.len();
        while state.queue.front().and_then(|r| r["seq"].as_u64()).is_some_and(|s| s <= acknowledged) {
            state.queue.pop_front();
        }
        let gone = before - state.queue.len();
        state.shipped += gone as u64;
        Ok(gone)
    }
}

/// Now, as RFC 3339 UTC with milliseconds.
pub fn now_rfc3339() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let (secs, millis) = (now.as_secs() as i64, now.subsec_millis());
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Howard Hinnant's days-to-civil.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_become_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_454), (2026, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert!(now_rfc3339().ends_with('Z'));
    }

    #[test]
    fn a_full_queue_drops_the_oldest() {
        let r = Records::new("i".into());
        for _ in 0..BUFFER + 3 {
            r.push(json!({"kind": "authzen"}));
        }
        assert_eq!(r.queued(), BUFFER);
        assert_eq!(r.counts().1, 3);
    }
}
