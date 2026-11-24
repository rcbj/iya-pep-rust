// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The PEP's one credential to the service (D1): an RFC 7523 self-assertion
//! through `sts-remote-pep` for a DPoP-bound (RFC 9449) access token, on
//! every call this crate makes.
//!
//! - **One key** signs the assertion and every proof, so each token is
//!   bound to the key the service registered for the PEP's entry. The file
//!   is read again when it changes, and a changed key drops every token.
//! - **Three audiences, one token each** ([`Audience`]), used until 30 s
//!   before it expires.
//! - **DPoP nonces:** `use_dpop_nonce` (a 400 at the token endpoint, a 401
//!   at a resource) is answered by one retry with the nonce handed. The
//!   latest nonce is kept per origin and role.
//! - **A refused token is replaced once:** a 401 `invalid_token` drops it
//!   and the call is made once more with a new one.
//! - **A refused grant is not asked again for five seconds.**
//! - **Fail closed:** a call with no token is not made. The caller gets the
//!   error, and a decision that needed it is `Unavailable`.
//! - **No token, key or proof is ever logged or returned.**

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::PepConfig;
use crate::error::PepError;
use crate::http::{htu, Answer, Body, Client};
use crate::key::{b64url, random_id, SigningKey};

/// The token endpoint, under the PDP URL.
pub const TOKEN_PATH: &str = "/oauth2/token";
const JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const ASSERTION_LIFETIME_S: u64 = 120;
const RENEW_BEFORE_S: u64 = 30;
const REFUSED_HOLD: Duration = Duration::from_secs(5);

/// The three audiences a token is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Audience {
    /// `/xacml/pep/*` and `POST /xacml/pip`: `xacml:pep`.
    Pep,
    /// `POST /admin-api/pep-audit`: `xacml:pep-audit`.
    Audit,
    /// `POST /access/v1/evaluation`: `authzen:evaluate`.
    Access,
}

impl Audience {
    pub const ALL: [Audience; 3] = [Audience::Pep, Audience::Audit, Audience::Access];

    fn index(self) -> usize {
        self as usize
    }

    /// The resource indicator's path under the PDP URL.
    pub fn path(self) -> &'static str {
        match self {
            Audience::Pep => "/xacml/pep",
            Audience::Audit => "/admin-api",
            Audience::Access => "/access/v1",
        }
    }

    pub fn scope(self) -> &'static str {
        match self {
            Audience::Pep => "xacml:pep",
            Audience::Audit => "xacml:pep-audit",
            Audience::Access => "authzen:evaluate",
        }
    }
}

struct Held {
    value: String,
    renew_at: Instant,
}

struct LoadedKey {
    key: Arc<SigningKey>,
    modified: Option<SystemTime>,
}

/// The credential.
pub struct Credential {
    name: String,
    client_id: String,
    base: String,
    key_path: PathBuf,
    client: Client,
    key: RwLock<LoadedKey>,
    tokens: Mutex<[Option<Held>; 3]>,
    refused_until: Mutex<[Option<(Instant, String)>; 3]>,
    gates: [Mutex<()>; 3],
    nonces: Mutex<HashMap<String, String>>,
}

fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn origin(url: &str) -> String {
    url::Url::parse(url).map(|u| u.origin().ascii_serialization()).unwrap_or_default()
}

fn read_key(path: &PathBuf) -> Result<LoadedKey, PepError> {
    let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    let pem = std::fs::read_to_string(path).map_err(|err| PepError::new("config", format!("the assertion key {} could not be read: {err}", path.display())))?;
    Ok(LoadedKey { key: Arc::new(SigningKey::from_pem(&pem)?), modified })
}

impl Credential {
    /// Reads the key; a key that can't be used is refused here, at start.
    pub fn new(config: &PepConfig, client: Client) -> Result<Self, PepError> {
        let key_path = PathBuf::from(&config.assertion_key);
        let key = read_key(&key_path)?;
        Ok(Self {
            name: config.name.clone(),
            client_id: config.client_id.clone(),
            base: config.base().to_string(),
            key_path,
            client,
            key: RwLock::new(key),
            tokens: Mutex::new([None, None, None]),
            refused_until: Mutex::new([None, None, None]),
            gates: [Mutex::new(()), Mutex::new(()), Mutex::new(())],
            nonces: Mutex::new(HashMap::new()),
        })
    }

    /// The key's RFC 7638 thumbprint, for the host library's check that its
    /// own keys differ.
    pub fn thumbprint(&self) -> String {
        self.key.read().unwrap_or_else(|e| e.into_inner()).key.thumbprint().to_string()
    }

    /// Reads the key again when its file changed. A key that no longer
    /// loads keeps the one held, and the error is returned. A changed key
    /// drops every token.
    pub fn reload_key(&self) -> Result<bool, PepError> {
        let modified = std::fs::metadata(&self.key_path).and_then(|m| m.modified()).ok();
        if modified == self.key.read().unwrap_or_else(|e| e.into_inner()).modified {
            return Ok(false);
        }
        let loaded = read_key(&self.key_path)?;
        let changed = {
            let mut held = self.key.write().unwrap_or_else(|e| e.into_inner());
            let changed = held.key.thumbprint() != loaded.key.thumbprint();
            *held = loaded;
            changed
        };
        if changed {
            *self.tokens.lock().unwrap_or_else(|e| e.into_inner()) = [None, None, None];
        }
        Ok(changed)
    }

    fn signing_key(&self) -> Arc<SigningKey> {
        self.key.read().unwrap_or_else(|e| e.into_inner()).key.clone()
    }

    fn nonce(&self, url: &str, role: &str) -> Option<String> {
        self.nonces.lock().unwrap_or_else(|e| e.into_inner()).get(&format!("{} {role}", origin(url))).cloned()
    }

    fn remember_nonce(&self, url: &str, role: &str, answer: &Answer) {
        let nonce = answer.dpop_nonce.trim();
        if !nonce.is_empty() {
            self.nonces.lock().unwrap_or_else(|e| e.into_inner()).insert(format!("{} {role}", origin(url)), nonce.to_string());
        }
    }

    fn proof(&self, method: &str, url: &str, token: Option<&str>, nonce: Option<&str>) -> String {
        let key = self.signing_key();
        let mut claims = json!({"jti": random_id(), "htm": method, "htu": htu(url), "iat": now_s()});
        if let Some(token) = token {
            claims["ath"] = Value::String(b64url(&Sha256::digest(token.as_bytes())));
        }
        if let Some(nonce) = nonce {
            claims["nonce"] = Value::String(nonce.to_string());
        }
        key.jws(json!({"typ": "dpop+jwt", "jwk": key.jwk()}), &claims)
    }

    fn assertion(&self, audience: &str) -> String {
        let now = now_s();
        let claims = json!({
            "iss": self.name, "sub": self.name, "aud": audience,
            "iat": now, "exp": now + ASSERTION_LIFETIME_S, "jti": random_id()
        });
        self.signing_key().jws(json!({"typ": "JWT"}), &claims)
    }

    fn fresh(&self, audience: Audience) -> Option<String> {
        let tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        tokens[audience.index()].as_ref().filter(|h| Instant::now() < h.renew_at).map(|h| h.value.clone())
    }

    /// Drops the token held for `audience` when it is still `token`.
    pub fn drop_token(&self, audience: Audience, token: &str) {
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        if tokens[audience.index()].as_ref().is_some_and(|h| h.value == token) {
            tokens[audience.index()] = None;
        }
    }

    /// Whether a token is held for `audience`, for the PEP's status.
    pub fn holds(&self, audience: Audience) -> bool {
        self.fresh(audience).is_some()
    }

    /// The token for `audience`: the one held, or one fetch shared by every
    /// caller waiting for it.
    pub fn token(&self, audience: Audience) -> Result<String, PepError> {
        if let Some(token) = self.fresh(audience) {
            return Ok(token);
        }
        let _gate = self.gates[audience.index()].lock().unwrap_or_else(|e| e.into_inner());
        if let Some(token) = self.fresh(audience) {
            return Ok(token);
        }
        if let Some((until, why)) = &self.refused_until.lock().unwrap_or_else(|e| e.into_inner())[audience.index()] {
            if Instant::now() < *until {
                return Err(PepError::new("refused", why.clone()));
            }
        }
        match self.fetch(audience) {
            Ok(held) => {
                let value = held.value.clone();
                self.tokens.lock().unwrap_or_else(|e| e.into_inner())[audience.index()] = Some(held);
                self.refused_until.lock().unwrap_or_else(|e| e.into_inner())[audience.index()] = None;
                Ok(value)
            }
            Err(err) => {
                if err.code == "refused" {
                    self.refused_until.lock().unwrap_or_else(|e| e.into_inner())[audience.index()] = Some((Instant::now() + REFUSED_HOLD, err.message.clone()));
                }
                Err(err)
            }
        }
    }

    fn fetch(&self, audience: Audience) -> Result<Held, PepError> {
        let token_url = format!("{}{TOKEN_PATH}", self.base);
        let mut retried = false;
        loop {
            let nonce = self.nonce(&token_url, "token");
            let dpop = self.proof("POST", &token_url, None, nonce.as_deref());
            let form = [
                ("grant_type", JWT_BEARER.to_string()),
                ("assertion", self.assertion(&token_url)),
                ("client_id", self.client_id.clone()),
                ("scope", audience.scope().to_string()),
                ("resource", format!("{}{}", self.base, audience.path())),
            ];
            let answer = self.client.send("POST", &token_url, &[("DPoP", dpop), ("Accept", "application/json".into())], Some(Body::Form(&form)))?;
            self.remember_nonce(&token_url, "token", &answer);
            let json = answer.json().unwrap_or(Value::Null);
            let error = json["error"].as_str().unwrap_or("");
            if answer.status == 400 && error == "use_dpop_nonce" && !retried && !answer.dpop_nonce.is_empty() {
                retried = true;
                continue;
            }
            if answer.status != 200 {
                let description = json["error_description"].as_str().unwrap_or("");
                return Err(PepError::new(
                    "refused",
                    format!("the token endpoint refused {} for {}: {} {} {}", audience.scope(), self.name, answer.status, error, description).trim_end().to_string(),
                ));
            }
            let Some(value) = json["access_token"].as_str().filter(|t| !t.is_empty()) else {
                return Err(PepError::new("transport", "the token endpoint answered 200 without an access_token"));
            };
            if !json["token_type"].as_str().unwrap_or("").eq_ignore_ascii_case("DPoP") {
                return Err(PepError::new("refused", "the token endpoint issued a token that is not DPoP-bound"));
            }
            let expires_in = json["expires_in"].as_u64().unwrap_or(60);
            return Ok(Held { value: value.to_string(), renew_at: Instant::now() + Duration::from_secs(expires_in.saturating_sub(RENEW_BEFORE_S)) });
        }
    }

    /// One call to a resource of `audience`, with its token and a proof. A
    /// nonce demand is answered once, and a refused token is replaced once.
    pub fn call(&self, audience: Audience, method: &str, url: &str, accept: &str, extra: &[(&str, String)], body: Option<&Body<'_>>) -> Result<Answer, PepError> {
        let role = audience.scope();
        let mut nonce_retried = false;
        let mut token_replaced = false;
        loop {
            let token = self.token(audience)?;
            let nonce = self.nonce(url, role);
            let mut headers = vec![
                ("Authorization", format!("DPoP {token}")),
                ("DPoP", self.proof(method, url, Some(&token), nonce.as_deref())),
                ("Accept", accept.to_string()),
            ];
            headers.extend(extra.iter().cloned());
            let body = body.map(|b| match b {
                Body::Json(v) => Body::Json(v),
                Body::Form(f) => Body::Form(f),
                Body::Xml(x) => Body::Xml(x),
            });
            let answer = self.client.send(method, url, &headers, body)?;
            self.remember_nonce(url, role, &answer);
            if answer.status == 401 {
                let challenge = answer.www_authenticate.to_ascii_lowercase();
                if challenge.contains("use_dpop_nonce") && !nonce_retried && !answer.dpop_nonce.is_empty() {
                    nonce_retried = true;
                    continue;
                }
                if challenge.contains("invalid_token") && !token_replaced {
                    token_replaced = true;
                    self.drop_token(audience, &token);
                    continue;
                }
            }
            return Ok(answer);
        }
    }
}
