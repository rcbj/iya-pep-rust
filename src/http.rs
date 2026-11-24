// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! Back-channel HTTP to the service. Redirects are not followed and the
//! process proxy environment is ignored, as in the authentication libraries.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use crate::error::PepError;

/// The most a response body may be.
pub const MAX_BODY: usize = 8 * 1024 * 1024;

/// `User-Agent` on every request.
pub const USER_AGENT: &str = concat!("iya-pep-rust/", env!("CARGO_PKG_VERSION"));

/// One answer.
#[derive(Debug, Clone, Default)]
pub struct Answer {
    pub status: u16,
    pub content_type: String,
    pub body: String,
    /// `DPoP-Nonce`, or empty.
    pub dpop_nonce: String,
    /// `WWW-Authenticate`, every value joined, or empty.
    pub www_authenticate: String,
    /// `ETag`, or empty.
    pub etag: String,
}

impl Answer {
    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_str(&self.body).ok()
    }
}

/// A body.
pub enum Body<'a> {
    Json(&'a serde_json::Value),
    Form(&'a [(&'a str, String)]),
    Xml(&'a str),
}

/// An HTTP client with the configured trust anchors and timeout.
#[derive(Clone)]
pub struct Client {
    agent: ureq::Agent,
}

impl Client {
    /// `ca` is PEM trust anchors added to the system's, or empty.
    pub fn new(ca: &str, timeout: Duration) -> Result<Self, PepError> {
        let mut builder = ureq::AgentBuilder::new().timeout(timeout).redirects(0).try_proxy_from_env(false).user_agent(USER_AGENT);
        if !ca.trim().is_empty() {
            let mut tls = native_tls::TlsConnector::builder();
            let mut found = false;
            for block in ca.split("-----END CERTIFICATE-----") {
                let trimmed = block.trim();
                if !trimmed.contains("BEGIN CERTIFICATE") {
                    continue;
                }
                let one = format!("{trimmed}\n-----END CERTIFICATE-----\n");
                let cert = native_tls::Certificate::from_pem(one.as_bytes()).map_err(|_| PepError::new("config", "tlsCa is not a PEM trust anchor"))?;
                tls.add_root_certificate(cert);
                found = true;
            }
            if !found {
                return Err(PepError::new("config", "tlsCa holds no PEM certificate"));
            }
            let connector = tls.build().map_err(|err| PepError::new("config", format!("tlsCa: {err}")))?;
            builder = builder.tls_connector(Arc::new(connector));
        }
        Ok(Self { agent: builder.build() })
    }

    /// Sends one request. Any status is an `Answer`; only a transport
    /// failure is an error.
    pub fn send(&self, method: &str, url: &str, headers: &[(&str, String)], body: Option<Body<'_>>) -> Result<Answer, PepError> {
        let mut req = self.agent.request(method, url);
        for (name, value) in headers {
            req = req.set(name, value);
        }
        let result = match body {
            Some(Body::Json(value)) => req.set("Content-Type", "application/json").send_string(&value.to_string()),
            Some(Body::Form(pairs)) => req.send_form(&pairs.iter().map(|(k, v)| (*k, v.as_str())).collect::<Vec<_>>()),
            Some(Body::Xml(text)) => req.set("Content-Type", "application/xml").send_string(text),
            None if method == "POST" => req.send_string(""),
            None => req.call(),
        };
        let response = match result {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(err)) => return Err(PepError::new("transport", format!("{url}: {err}"))),
        };
        let header = |name: &str| response.header(name).unwrap_or("").to_string();
        let mut answer = Answer {
            status: response.status(),
            content_type: header("content-type"),
            dpop_nonce: header("dpop-nonce"),
            www_authenticate: response.all("www-authenticate").join(", "),
            etag: header("etag"),
            body: String::new(),
        };
        let mut buf = Vec::new();
        response
            .into_reader()
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|err| PepError::new("transport", format!("{url}: {err}")))?;
        if buf.len() > MAX_BODY {
            return Err(PepError::new("transport", format!("{url} answered more than {MAX_BODY} bytes")));
        }
        answer.body = String::from_utf8_lossy(&buf).into_owned();
        Ok(answer)
    }
}

/// `url` without its query and fragment: a DPoP proof's `htu`.
pub fn htu(url: &str) -> &str {
    let end = url.find(['?', '#']).unwrap_or(url.len());
    &url[..end]
}
