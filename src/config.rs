// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The PEP's configuration: the `pep` section of a library's configuration
//! file, read by the library and handed over.

use serde_json::Value;

use crate::error::PepError;

/// The client the PEP's self-assertion is presented through.
pub const DEFAULT_CLIENT_ID: &str = "sts-remote-pep";
/// `local` with no signal stream: how often the policy is pulled.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 15_000;
/// `local` with a signal stream: the pull that runs in case an event is lost.
pub const DEFAULT_FALLBACK_POLL_MS: u64 = 300_000;
pub const DEFAULT_HEARTBEAT_INTERVAL_MS: u64 = 30_000;
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;
/// The longest a cached Permit may live (`central`).
pub const MAX_PERMIT_CACHE_MS: u64 = 60_000;

/// Who decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Every decision is an AuthZEN evaluation at the service.
    Central,
    /// The engine decides in process over the bound application's policies
    /// (the `local` feature).
    Local,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Central => "central",
            Mode::Local => "local",
        }
    }
}

/// The configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PepConfig {
    /// The PEP's name: its service account's username, and `iss` and `sub`
    /// of its self-assertion.
    pub name: String,
    pub mode: Mode,
    /// The path of the PEP's private key, in PEM. Read again when it changes.
    pub assertion_key: String,
    pub client_id: String,
    /// The service, with `/realm/<id>` for a realm. The library derives a
    /// default from its issuer.
    pub pdp_url: String,
    /// The application the PEP is bound to (iya-sts#2025).
    pub application: String,
    pub poll_interval_ms: u64,
    pub fallback_poll_ms: u64,
    pub heartbeat_interval_ms: u64,
    /// Send each decision's record to the service's audit log.
    pub decision_records: bool,
    /// `central` only: how long a Permit is reused for one (subject, action,
    /// resource). 0, the default, is off.
    pub permit_cache_ms: u64,
    /// The host library has a signal stream and hands over
    /// `pep-policies-changed` events. Without one, `local` polls at
    /// `poll_interval_ms`.
    pub signals: bool,
    /// The obligation types the host application discharges itself, sent
    /// as `context.supported_obligations`.
    pub supported_obligations: Vec<String>,
    /// PEM trust anchors for the service's TLS, added to the system's.
    pub tls_ca: String,
    pub timeout_ms: u64,
}

impl PepConfig {
    /// The defaults around the four values nothing can default.
    pub fn new(name: &str, mode: Mode, assertion_key: &str, pdp_url: &str, application: &str) -> Self {
        Self {
            name: name.to_string(),
            mode,
            assertion_key: assertion_key.to_string(),
            client_id: DEFAULT_CLIENT_ID.to_string(),
            pdp_url: pdp_url.to_string(),
            application: application.to_string(),
            poll_interval_ms: DEFAULT_POLL_INTERVAL_MS,
            fallback_poll_ms: DEFAULT_FALLBACK_POLL_MS,
            heartbeat_interval_ms: DEFAULT_HEARTBEAT_INTERVAL_MS,
            decision_records: true,
            permit_cache_ms: 0,
            signals: false,
            supported_obligations: Vec::new(),
            tls_ca: String::new(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    /// Reads a `pep` JSON section (camelCase members). `pdp_url` and
    /// `application` may be absent there when the library supplies them;
    /// pass them as defaults. An unknown member is refused, so a misspelt
    /// one is not silently ignored.
    pub fn from_json(section: &Value, default_pdp_url: &str, default_application: &str) -> Result<Self, PepError> {
        let Some(map) = section.as_object() else {
            return Err(PepError::new("config", "pep must be an object"));
        };
        const KNOWN: &[&str] = &[
            "name", "mode", "assertionKey", "clientId", "pdpUrl", "application", "pollIntervalMs", "fallbackPollMs",
            "heartbeatIntervalMs", "decisionRecords", "permitCacheMs", "signals", "supportedObligations", "tlsCa", "timeoutMs",
        ];
        if let Some(unknown) = map.keys().find(|k| !KNOWN.contains(&k.as_str())) {
            return Err(PepError::new("config", format!("pep.{unknown} is not a setting")));
        }
        let text = |key: &str, default: &str| -> Result<String, PepError> {
            match map.get(key) {
                None | Some(Value::Null) => Ok(default.to_string()),
                Some(Value::String(s)) => Ok(s.clone()),
                Some(_) => Err(PepError::new("config", format!("pep.{key} must be a string"))),
            }
        };
        let number = |key: &str, default: u64| -> Result<u64, PepError> {
            match map.get(key) {
                None | Some(Value::Null) => Ok(default),
                Some(v) => v.as_u64().ok_or_else(|| PepError::new("config", format!("pep.{key} must be a non-negative integer"))),
            }
        };
        let flag = |key: &str, default: bool| -> Result<bool, PepError> {
            match map.get(key) {
                None | Some(Value::Null) => Ok(default),
                Some(v) => v.as_bool().ok_or_else(|| PepError::new("config", format!("pep.{key} must be true or false"))),
            }
        };
        let mode = match text("mode", "central")?.as_str() {
            "central" => Mode::Central,
            "local" => Mode::Local,
            other => return Err(PepError::new("config", format!("pep.mode is \"{other}\"; it must be central or local"))),
        };
        let supported_obligations = match map.get("supportedObligations") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| v.as_str().map(str::to_string).ok_or_else(|| PepError::new("config", "pep.supportedObligations must be strings")))
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(PepError::new("config", "pep.supportedObligations must be an array")),
        };
        let config = Self {
            name: text("name", "")?,
            mode,
            assertion_key: text("assertionKey", "")?,
            client_id: text("clientId", DEFAULT_CLIENT_ID)?,
            pdp_url: text("pdpUrl", default_pdp_url)?,
            application: text("application", default_application)?,
            poll_interval_ms: number("pollIntervalMs", DEFAULT_POLL_INTERVAL_MS)?,
            fallback_poll_ms: number("fallbackPollMs", DEFAULT_FALLBACK_POLL_MS)?,
            heartbeat_interval_ms: number("heartbeatIntervalMs", DEFAULT_HEARTBEAT_INTERVAL_MS)?,
            decision_records: flag("decisionRecords", true)?,
            permit_cache_ms: number("permitCacheMs", 0)?,
            signals: flag("signals", false)?,
            supported_obligations,
            tls_ca: text("tlsCa", "")?,
            timeout_ms: number("timeoutMs", DEFAULT_TIMEOUT_MS)?,
        };
        config.validate()?;
        Ok(config)
    }

    /// Refuses a configuration the PEP can't run with.
    pub fn validate(&self) -> Result<(), PepError> {
        let bad = |message: String| Err(PepError::new("config", message));
        if self.name.is_empty() || self.name.len() > 128 || !self.name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
            return bad("pep.name must be 1 to 128 characters of [A-Za-z0-9._-]".into());
        }
        if self.assertion_key.is_empty() {
            return bad("pep.assertionKey must name the PEP's private key file".into());
        }
        if self.client_id.is_empty() {
            return bad("pep.clientId must not be empty".into());
        }
        match url::Url::parse(&self.pdp_url) {
            Ok(u) if (u.scheme() == "https" || u.scheme() == "http") && u.host_str().is_some() && u.query().is_none() && u.fragment().is_none() => {}
            _ => return bad(format!("pep.pdpUrl \"{}\" is not an http(s) URL without a query", self.pdp_url)),
        }
        if self.application.is_empty() {
            return bad("pep.application must name the application the PEP is bound to".into());
        }
        if self.mode == Mode::Local && !cfg!(feature = "local") {
            return bad("pep.mode is local, and this build has no engine (the iya-pep `local` feature)".into());
        }
        for (key, value, min) in [
            ("pollIntervalMs", self.poll_interval_ms, 1000),
            ("fallbackPollMs", self.fallback_poll_ms, 1000),
            ("heartbeatIntervalMs", self.heartbeat_interval_ms, 1000),
            ("timeoutMs", self.timeout_ms, 100),
        ] {
            if !(min..=86_400_000).contains(&value) {
                return bad(format!("pep.{key} must be from {min} to 86400000"));
            }
        }
        if self.permit_cache_ms > MAX_PERMIT_CACHE_MS {
            return bad(format!("pep.permitCacheMs must be at most {MAX_PERMIT_CACHE_MS}"));
        }
        if self.permit_cache_ms > 0 && self.mode == Mode::Local {
            return bad("pep.permitCacheMs is for central mode; a local PEP decides in process".into());
        }
        Ok(())
    }

    /// The service's base URL, without a trailing slash.
    pub fn base(&self) -> &str {
        self.pdp_url.trim_end_matches('/')
    }

    /// The realm's id from `/realm/<id>`, or empty for the default realm.
    pub fn realm(&self) -> String {
        let Ok(u) = url::Url::parse(&self.pdp_url) else { return String::new() };
        let segments: Vec<&str> = u.path_segments().map(|s| s.filter(|p| !p.is_empty()).collect()).unwrap_or_default();
        match segments.iter().position(|s| *s == "realm") {
            Some(i) => segments.get(i + 1).map(|s| s.to_string()).unwrap_or_default(),
            None => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_section_reads_with_defaults_and_refuses_unknown_members() {
        let c = PepConfig::from_json(&json!({"name": "pep-1", "assertionKey": "/k.pem"}), "https://sts.example/realm/r1/", "app").unwrap();
        assert_eq!(c.mode, Mode::Central);
        assert_eq!(c.client_id, DEFAULT_CLIENT_ID);
        assert_eq!(c.base(), "https://sts.example/realm/r1");
        assert_eq!(c.realm(), "r1");
        assert_eq!(c.fallback_poll_ms, 300_000);
        let err = PepConfig::from_json(&json!({"name": "p", "assertionKey": "k", "polIntervalMs": 5}), "https://s", "a").unwrap_err();
        assert!(err.message.contains("polIntervalMs"), "{err}");
    }

    #[test]
    fn bad_values_are_refused() {
        let base = |extra: Value| {
            let mut v = json!({"name": "pep-1", "assertionKey": "/k.pem"});
            for (k, x) in extra.as_object().unwrap() {
                v[k] = x.clone();
            }
            PepConfig::from_json(&v, "https://sts.example", "app")
        };
        assert!(base(json!({"mode": "remote"})).is_err());
        assert!(base(json!({"name": "a b"})).is_err());
        assert!(base(json!({"pdpUrl": "ftp://x"})).is_err());
        assert!(base(json!({"pollIntervalMs": 10})).is_err());
        assert!(base(json!({"permitCacheMs": 120000})).is_err());
        assert!(base(json!({"application": ""})).is_err());
        assert_eq!(PepConfig::from_json(&json!({"name": "p", "assertionKey": "k"}), "https://sts.example", "a").unwrap().realm(), "");
    }
}
