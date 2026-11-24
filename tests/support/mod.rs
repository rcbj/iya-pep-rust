// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! A stub PDP: the service's token endpoint, control plane, PIP, AuthZEN
//! evaluation and decision-record door, on a real socket, recording every
//! request it is sent. Each behaviour the tests need is a switch.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};

pub const REALM: &str = "r1";
pub const NAME: &str = "pep-orders";
/// The DN the stub's registration answer names as the PEP's entry.
pub const IDENTITY: &str = "cn=pep-orders,ou=users,dc=example,dc=com";
pub const APP: &str = "orders";

/// One request the stub was sent.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }

    pub fn form(&self, key: &str) -> Option<String> {
        url::form_urlencoded::parse(self.body.as_bytes()).find(|(k, _)| k == key).map(|(_, v)| v.into_owned())
    }

    /// The claims of the DPoP proof.
    pub fn proof(&self) -> Value {
        claims(self.header("DPoP").unwrap_or(""))
    }

    pub fn proof_header(&self) -> Value {
        part(self.header("DPoP").unwrap_or(""), 0)
    }
}

fn part(jws: &str, index: usize) -> Value {
    jws.split('.').nth(index).and_then(|p| URL_SAFE_NO_PAD.decode(p).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null)
}

/// The claims of a compact JWS.
pub fn claims(jws: &str) -> Value {
    part(jws, 1)
}

/// A scripted answer: the status, the body and extra headers.
pub type Scripted = (u16, Value, Vec<(String, String)>);

/// What the stub answers; tests change it while the PEP runs.
pub struct Script {
    /// The token endpoint asks for a nonce on the first grant.
    pub token_nonce_first: bool,
    /// The token endpoint refuses every grant.
    pub token_refused: bool,
    /// Answers for `POST /access/v1/evaluation`, taken in order; when empty,
    /// `evaluation_default`.
    pub evaluations: VecDeque<Scripted>,
    pub evaluation_default: (u16, Value),
    /// The heartbeat's status and `current`.
    pub heartbeat_status: u16,
    pub heartbeat_current: bool,
    /// The policy set and its token.
    pub policies: Vec<Value>,
    pub policy_token: String,
    pub catalogue_rows: Vec<Value>,
    pub catalogue_token: String,
    pub obligations_profile: bool,
    /// The PIP's answer body.
    pub pip_answer: String,
    pub register_status: u16,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            token_nonce_first: false,
            token_refused: false,
            evaluations: VecDeque::new(),
            evaluation_default: (200, json!({"decision": true})),
            heartbeat_status: 200,
            heartbeat_current: true,
            policies: Vec::new(),
            policy_token: "p1".into(),
            catalogue_rows: Vec::new(),
            catalogue_token: "c1".into(),
            obligations_profile: false,
            pip_answer: String::new(),
            register_status: 201,
        }
    }
}

pub struct Stub {
    pub base: String,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub script: Arc<Mutex<Script>>,
    server: Arc<tiny_http::Server>,
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.server.unblock();
    }
}

impl Stub {
    pub fn start() -> Stub {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("the stub binds"));
        let port = server.server_addr().to_ip().expect("an IP address").port();
        let base = format!("http://127.0.0.1:{port}/realm/{REALM}");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(Mutex::new(Script::default()));
        let (s, sc, srv, b) = (seen.clone(), script.clone(), server.clone(), base.clone());
        thread::spawn(move || {
            let mut tokens = 0u32;
            let mut nonce_asked = false;
            for mut request in srv.incoming_requests() {
                let mut body = String::new();
                let _ = request.as_reader().read_to_string(&mut body);
                let url = request.url().to_string();
                let (path, query) = match url.split_once('?') {
                    Some((p, q)) => (p.to_string(), q.to_string()),
                    None => (url.clone(), String::new()),
                };
                let one = Seen {
                    method: request.method().to_string(),
                    path: path.clone(),
                    query,
                    headers: request.headers().iter().map(|h| (h.field.to_string(), h.value.to_string())).collect(),
                    body,
                };
                s.lock().unwrap().push(one.clone());
                let (status, out, headers) = answer(&b, &one, &mut sc.lock().unwrap(), &mut tokens, &mut nonce_asked);
                let mut response = tiny_http::Response::from_string(out).with_status_code(status);
                for (name, value) in headers {
                    response.add_header(tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap());
                }
                let _ = request.respond(response);
            }
        });
        Stub { base, seen, script, server }
    }

    pub fn seen(&self, path_ends: &str) -> Vec<Seen> {
        self.seen.lock().unwrap().iter().filter(|s| s.path.ends_with(path_ends)).cloned().collect()
    }

    pub fn count(&self, path_ends: &str) -> usize {
        self.seen(path_ends).len()
    }

    /// Waits up to `limit` for `f` to hold.
    pub fn wait(&self, limit: Duration, mut f: impl FnMut(&Stub) -> bool) -> bool {
        let until = Instant::now() + limit;
        while Instant::now() < until {
            if f(self) {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }
        f(self)
    }
}

fn json_answer(status: u16, value: Value) -> (u16, String, Vec<(String, String)>) {
    (status, value.to_string(), vec![("Content-Type".into(), "application/json".into())])
}

fn answer(base: &str, r: &Seen, script: &mut Script, tokens: &mut u32, nonce_asked: &mut bool) -> (u16, String, Vec<(String, String)>) {
    let prefix = format!("/realm/{REALM}");
    let path = r.path.strip_prefix(&prefix).unwrap_or(&r.path);
    let authorized = r.header("Authorization").is_some_and(|a| a.starts_with("DPoP ")) && r.header("DPoP").is_some();
    match (r.method.as_str(), path) {
        ("POST", "/oauth2/token") => {
            if script.token_refused {
                return json_answer(400, json!({"error": "invalid_grant", "error_description": "no key is registered for the PEP"}));
            }
            if script.token_nonce_first && !*nonce_asked {
                *nonce_asked = true;
                let (s, b, mut h) = json_answer(400, json!({"error": "use_dpop_nonce"}));
                h.push(("DPoP-Nonce".into(), "n-token".into()));
                return (s, b, h);
            }
            *tokens += 1;
            let scope = r.form("scope").unwrap_or_default();
            json_answer(200, json!({"access_token": format!("tok-{scope}-{tokens}"), "token_type": "DPoP", "expires_in": 300}))
        }
        _ if !authorized => {
            let (s, b, mut h) = json_answer(401, json!({"error": "invalid_token"}));
            h.push(("WWW-Authenticate".into(), "DPoP error=\"invalid_token\"".into()));
            (s, b, h)
        }
        ("POST", "/xacml/pep/register") => json_answer(script.register_status, json!({"registered": true, "name": NAME, "created": true, "identity": IDENTITY})),
        ("POST", "/xacml/pep/heartbeat") => {
            json_answer(script.heartbeat_status, json!({"acknowledged": true, "name": NAME, "syncToken": script.policy_token, "current": script.heartbeat_current, "action": ""}))
        }
        ("GET", "/xacml/pep/policies") => {
            let etag = format!("\"{}\"", script.policy_token);
            if r.header("If-None-Match") == Some(etag.as_str()) {
                return (304, String::new(), vec![("ETag".into(), etag)]);
            }
            let (s, b, mut h) = json_answer(200, json!({"syncToken": script.policy_token, "root": "root", "policies": script.policies, "withheld": [], "note": ""}));
            h.push(("ETag".into(), etag));
            (s, b, h)
        }
        ("GET", "/xacml/pep/authzen-catalogue") => {
            let etag = format!("\"{}\"", script.catalogue_token);
            if r.header("If-None-Match") == Some(etag.as_str()) {
                return (304, String::new(), vec![("ETag".into(), etag)]);
            }
            let body = json!({
                "syncToken": script.catalogue_token, "realm": REALM, "apiObject": null, "rows": script.catalogue_rows, "leftOut": 0,
                "settings": {"enabled": true, "resolveSubjectTypes": ["user"], "batchEnabled": true, "maxEvaluations": 100, "maxBodyBytes": 65536,
                             "returnReasons": false, "obligationsProfile": script.obligations_profile, "tokenExchange": false,
                             "tokenExchangeDetailTypes": [], "tokenExchangeTokenTypes": []},
                "note": ""
            });
            let (s, b, mut h) = json_answer(200, body);
            h.push(("ETag".into(), etag));
            (s, b, h)
        }
        ("POST", "/xacml/pip") => (200, script.pip_answer.clone(), vec![("Content-Type".into(), "application/xml".into())]),
        ("POST", "/access/v1/evaluation") => {
            let (status, value, extra) = script.evaluations.pop_front().unwrap_or_else(|| (script.evaluation_default.0, script.evaluation_default.1.clone(), Vec::new()));
            let (s, b, mut h) = json_answer(status, value);
            h.extend(extra);
            (s, b, h)
        }
        ("POST", "/admin-api/pep-audit") => {
            let last = r.json()["events"].as_array().and_then(|e| e.last()).and_then(|e| e["seq"].as_u64()).unwrap_or(0);
            json_answer(200, json!({"acknowledged": last, "recorded": 1, "duplicates": 0, "ignored": 0, "recording": true}))
        }
        _ => {
            let _ = base;
            json_answer(404, json!({"error": "not_found"}))
        }
    }
}

/// A P-256 key written to a temporary file; returns its path.
pub fn key_file(tag: &str) -> String {
    use p256::pkcs8::EncodePrivateKey;
    let key = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
    let pem = key.to_pkcs8_pem(Default::default()).unwrap().to_string();
    let path = std::env::temp_dir().join(format!("iya-pep-test-{tag}-{}.pem", std::process::id()));
    std::fs::write(&path, pem).unwrap();
    path.to_string_lossy().into_owned()
}
